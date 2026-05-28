"""Bounded source-available GitHub repo cases for sandbox execution."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Dict, List, Tuple

EXPERIMENTS_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLES_PATH = EXPERIMENTS_ROOT / "results" / "ecosystem" / "real_ecosystem_samples.jsonl"


@dataclass(frozen=True)
class GitHubRepoProfile:
    repo: str
    source_path: str
    description: str
    invoke: str


@dataclass(frozen=True)
class GitHubRepoCase:
    case_id: str
    repo: str
    url: str
    default_branch: str
    source_path: str
    description: str
    invoke: str
    source_paths: Tuple[str, ...]
    raw_url: str


_PROFILES: Tuple[GitHubRepoProfile, ...] = (
    GitHubRepoProfile(
        repo="ahujasid/blender-mcp",
        source_path="main.py",
        description="GitHub Python entrypoint that delegates to blender_mcp.server.main.",
        invoke=(
            "main()\n"
            "result = {'server_main_called': True}"
        ),
    ),
    GitHubRepoProfile(
        repo="BeehiveInnovations/pal-mcp-server",
        source_path="server.py",
        description="GitHub Python MCP server entrypoint with a populated tool registry.",
        invoke=(
            "result = {\n"
            "    'tool_count': len(TOOLS),\n"
            "    'has_version_tool': 'version' in TOOLS,\n"
            "    'has_listmodels_tool': 'listmodels' in TOOLS,\n"
            "    'server_name': getattr(server, 'name', None),\n"
            "}\n"
        ),
    ),
)


def _load_samples(samples_path: Path) -> Dict[str, dict]:
    samples: Dict[str, dict] = {}
    for line in samples_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        samples[str(payload.get("repo") or "")] = payload
    return samples


def _raw_url(repo: str, branch: str, source_path: str) -> str:
    owner, name = repo.split("/", 1)
    return f"https://raw.githubusercontent.com/{owner}/{name}/{branch}/{source_path}"


def build_github_repo_cases(samples_path: Path = DEFAULT_SAMPLES_PATH) -> List[GitHubRepoCase]:
    samples = _load_samples(samples_path)
    cases: List[GitHubRepoCase] = []
    for profile in _PROFILES:
        sample = samples.get(profile.repo)
        if not sample or sample.get("source") != "github_mcp":
            continue
        if sample.get("code_availability") != "source_available":
            continue
        source_paths = tuple(str(path) for path in sample.get("source_paths") or ())
        if profile.source_path not in source_paths:
            continue
        default_branch = str(sample.get("default_branch") or "main")
        cases.append(
            GitHubRepoCase(
                case_id=profile.repo.replace("/", "__"),
                repo=profile.repo,
                url=str(sample.get("url") or ""),
                default_branch=default_branch,
                source_path=profile.source_path,
                description=profile.description,
                invoke=profile.invoke,
                source_paths=source_paths,
                raw_url=_raw_url(profile.repo, default_branch, profile.source_path),
            )
        )
    return cases
