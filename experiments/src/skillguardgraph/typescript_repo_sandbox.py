"""Bounded source-available TypeScript/JavaScript GitHub repo cases for sandbox execution."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Dict, List, Tuple

EXPERIMENTS_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLES_PATH = EXPERIMENTS_ROOT / "results" / "ecosystem" / "real_ecosystem_samples.jsonl"


@dataclass(frozen=True)
class TypeScriptRepoProfile:
    repo: str
    source_path: str
    description: str
    invoke: str


@dataclass(frozen=True)
class TypeScriptRepoCase:
    case_id: str
    repo: str
    url: str
    default_branch: str
    source_path: str
    description: str
    invoke: str
    source_paths: Tuple[str, ...]
    raw_url: str


_PROFILES: Tuple[TypeScriptRepoProfile, ...] = (
    TypeScriptRepoProfile(
        repo="21st-dev/magic-mcp",
        source_path="src/index.ts",
        description="TypeScript MCP server entrypoint registering four tools and connecting a stdio transport.",
        invoke=(
            "result = {\n"
            "  toolCount: globalThis.__sgg.server?.registeredTools?.length ?? 0,\n"
            "  connected: Boolean(globalThis.__sgg.server?.connected),\n"
            "  consoleConfigured: Boolean(globalThis.__sgg.consoleConfigured),\n"
            "};\n"
        ),
    ),
    TypeScriptRepoProfile(
        repo="Done-0/fuck-u-code",
        source_path="src/index.ts",
        description="TypeScript CLI wrapper that delegates to runCLI with translated fatal-error handling.",
        invoke=(
            "result = {\n"
            "  runCliCalls: globalThis.__sgg.runCliCalls ?? 0,\n"
            "  translationCalls: globalThis.__sgg.translationCalls ?? 0,\n"
            "};\n"
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


def build_typescript_repo_cases(samples_path: Path = DEFAULT_SAMPLES_PATH) -> List[TypeScriptRepoCase]:
    samples = _load_samples(samples_path)
    cases: List[TypeScriptRepoCase] = []
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
            TypeScriptRepoCase(
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
