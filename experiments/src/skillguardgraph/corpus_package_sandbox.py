"""Corpus-derived third-party package cases for bounded sandbox execution."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Dict, List, Tuple

EXPERIMENTS_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SAMPLES_PATH = EXPERIMENTS_ROOT / "results" / "ecosystem" / "real_ecosystem_samples.jsonl"


@dataclass(frozen=True)
class CorpusPackageProfile:
    package_name: str
    source_path: str
    description: str
    sdist_url: str
    invoke: str


@dataclass(frozen=True)
class CorpusPackageCase:
    case_id: str
    package_name: str
    version: str
    artifact_url: str
    linked_repository: str | None
    source_path: str
    description: str
    invoke: str
    sdist_url: str
    source_paths: Tuple[str, ...]


_PROFILES: Tuple[CorpusPackageProfile, ...] = (
    CorpusPackageProfile(
        package_name="autodoc-mcp",
        source_path="test_mcp_server.py",
        description="PyPI integration test exercising import, tempfile, and subprocess smoke checks.",
        sdist_url="https://files.pythonhosted.org/packages/93/2a/a4620c8e6165e6d7291eb2d1f05fe75cd1ada6615f00b4f7f4cdf80cccbf/autodoc_mcp-0.5.1.tar.gz",
        invoke=(
            "tester = TestMCPServerIntegration()\n"
            "tester.test_server_help_command()\n"
            "tester.test_basic_imports_work()\n"
            "tester.test_toml_file_validation()\n"
            "result = {'tests_executed': 3}"
        ),
    ),
    CorpusPackageProfile(
        package_name="mcp-server-creator",
        source_path="test_mcp_creator.py",
        description="PyPI package test script that drives a FastMCP client against a server-creator package.",
        sdist_url="https://files.pythonhosted.org/packages/36/2d/175239ecffdfc2a3b285c1d9bd3f382d319bcb9c551b6252e3734a582b82/mcp_server_creator-0.1.3.tar.gz",
        invoke=(
            "import asyncio\n"
            "import json\n"
            "async def _run_fixture():\n"
            "    client = Client('mcp_server_creator.mcp_server_creator')\n"
            "    async with client:\n"
            "        created = await client.call_tool('create_server', {'name': 'Test Server', 'description': 'Validation server', 'version': '0.1.0'})\n"
            "        added = await client.call_tool('add_tool', {'server_id': 'test_server', 'tool_name': 'echo', 'description': 'Echo', 'parameters': [{'name': 'message', 'type': 'str'}], 'return_type': 'str', 'implementation': \"    return message\"})\n"
            "        return {\n"
            "            'create_server_success': json.loads(created[0].text)['success'],\n"
            "            'add_tool_success': json.loads(added[0].text)['success'],\n"
            "        }\n"
            "result = asyncio.run(_run_fixture())"
        ),
    ),
    CorpusPackageProfile(
        package_name="search-mcp-server",
        source_path="mcp_server.py",
        description="PyPI MCP server module with registered tools/resources and mocked catalog data.",
        sdist_url="https://files.pythonhosted.org/packages/05/14/e0e56d1eaf68ce177afaebf6d3746dabfe2ddaf3831075430481676ea593/search_mcp_server-0.2.0.tar.gz",
        invoke=(
            "import asyncio\n"
            "async def _fake_get_servers_data():\n"
            "    return [\n"
            "        {'name': 'browser-tools', 'description': 'Inspect browser logs', 'category': 'development', 'url': 'https://example.invalid/browser-tools'},\n"
            "        {'name': 'threat-hunt', 'description': 'Threat intel search', 'category': 'security', 'url': 'https://example.invalid/threat-hunt'},\n"
            "    ]\n"
            "get_servers_data = _fake_get_servers_data\n"
            "async def _run_fixture():\n"
            "    search_result = await search_mcp_servers('browser', 'all')\n"
            "    categories = await get_mcp_server_categories()\n"
            "    all_servers = await get_all_mcp_servers()\n"
            "    return {\n"
            "        'search_total_results': search_result['total_results'],\n"
            "        'tool_count': len(mcp._tools),\n"
            "        'resource_count': len(mcp._resources),\n"
            "        'category_total': categories['total_categories'],\n"
            "        'all_servers_len': len(all_servers),\n"
            "    }\n"
            "result = asyncio.run(_run_fixture())"
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


def build_corpus_package_cases(samples_path: Path = DEFAULT_SAMPLES_PATH) -> List[CorpusPackageCase]:
    samples = _load_samples(samples_path)
    cases: List[CorpusPackageCase] = []
    for profile in _PROFILES:
        sample = samples.get(profile.package_name)
        if not sample or sample.get("source") != "pypi_mcp":
            continue
        if sample.get("code_availability") != "source_available":
            continue
        source_paths = tuple(str(path) for path in sample.get("source_paths") or ())
        if profile.source_path not in source_paths:
            continue
        cases.append(
            CorpusPackageCase(
                case_id=profile.package_name,
                package_name=profile.package_name,
                version=str(sample.get("package_version") or sample.get("manifest", {}).get("version") or ""),
                artifact_url=str(sample.get("url") or ""),
                linked_repository=sample.get("linked_repository"),
                source_path=profile.source_path,
                description=profile.description,
                invoke=profile.invoke,
                sdist_url=profile.sdist_url,
                source_paths=source_paths,
            )
        )
    return cases
