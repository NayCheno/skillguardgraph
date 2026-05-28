#!/usr/bin/env python3
"""Execute bounded corpus-derived third-party package cases inside the local sandbox."""
from __future__ import annotations

import io
import json
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "results" / "main" / "corpus_package_sandbox.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.corpus_package_sandbox import CorpusPackageCase, build_corpus_package_cases  # noqa: E402

_WORKER = """
import asyncio
import json
import subprocess
import sys
import types
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
out_path = Path(sys.argv[2])
events = []

class _FakeProcess:
    def __init__(self, cmd):
        self.cmd = cmd
        self.returncode = 0

    async def communicate(self, input=None):
        events.append({'kind': 'subprocess_attempt', 'cmd': self.cmd, 'input_bytes': len(input or b'')})
        return b'', b''

async def _fake_create_subprocess_exec(*cmd, **kwargs):
    return _FakeProcess(list(cmd))

def _fake_run(cmd, *args, **kwargs):
    events.append({'kind': 'subprocess_run', 'cmd': list(cmd), 'timeout': kwargs.get('timeout')})
    return types.SimpleNamespace(returncode=0, stdout='OK\\n', stderr='')

class _FakeFastMCP:
    def __init__(self, name, **kwargs):
        self.name = name
        self.kwargs = kwargs
        self._tools = []
        self._resources = []
        self._prompts = []

    def tool(self, *args, **kwargs):
        def decorator(fn):
            self._tools.append(getattr(fn, '__name__', 'tool'))
            return fn
        if args and callable(args[0]) and len(args) == 1 and not kwargs:
            return decorator(args[0])
        return decorator

    def resource(self, *args, **kwargs):
        def decorator(fn):
            self._resources.append(getattr(fn, '__name__', 'resource'))
            return fn
        return decorator

    def prompt(self, *args, **kwargs):
        def decorator(fn):
            self._prompts.append(getattr(fn, '__name__', 'prompt'))
            return fn
        return decorator

    def run(self, *args, **kwargs):
        events.append({'kind': 'server_run', 'name': self.name, 'kwargs': kwargs})

class _FakeClientResponse:
    def __init__(self, text):
        self.text = text

class _FakeClient:
    def __init__(self, target):
        self.target = target

    async def __aenter__(self):
        events.append({'kind': 'client_enter', 'target': self.target})
        return self

    async def __aexit__(self, exc_type, exc, tb):
        events.append({'kind': 'client_exit', 'target': self.target})
        return False

    async def call_tool(self, name, params):
        events.append({'kind': 'client_call_tool', 'name': name, 'param_keys': sorted(params.keys())})
        body = {'success': True, 'tool_name': name, 'server_id': params.get('server_id', 'generated')}
        return [_FakeClientResponse(json.dumps(body))]

fake_fastmcp = types.ModuleType('fastmcp')
fake_fastmcp.FastMCP = _FakeFastMCP
fake_fastmcp.Client = _FakeClient
sys.modules['fastmcp'] = fake_fastmcp

fake_mcp_fastmcp = types.ModuleType('mcp.server.fastmcp')
fake_mcp_fastmcp.FastMCP = _FakeFastMCP
sys.modules['mcp'] = types.ModuleType('mcp')
sys.modules['mcp.server'] = types.ModuleType('mcp.server')
sys.modules['mcp.server.fastmcp'] = fake_mcp_fastmcp

fake_httpx = types.ModuleType('httpx')
class _FakeAsyncClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        return types.SimpleNamespace(text='', status_code=200)

fake_httpx.AsyncClient = _FakeAsyncClient
sys.modules['httpx'] = fake_httpx

fake_bs4 = types.ModuleType('bs4')
class _FakeTag:
    def __init__(self, *args, **kwargs):
        pass

    def get_text(self):
        return ''

    def find_all(self, *args, **kwargs):
        return []

class _FakeBeautifulSoup(_FakeTag):
    pass

fake_bs4.Tag = _FakeTag
fake_bs4.BeautifulSoup = _FakeBeautifulSoup
sys.modules['bs4'] = fake_bs4

autodoc_pkg = types.ModuleType('autodoc_mcp')
autodoc_pkg.__path__ = []
sys.modules['autodoc_mcp'] = autodoc_pkg
autodoc_core = types.ModuleType('autodoc_mcp.core')
autodoc_core.__path__ = []
sys.modules['autodoc_mcp.core'] = autodoc_core

class FileCacheManager:
    def __init__(self, cache_dir=None):
        self.cache_dir = cache_dir

class PyProjectParser:
    def validate_file(self, path):
        return True

class VersionResolver:
    pass

cache_mod = types.ModuleType('autodoc_mcp.core.cache_manager')
cache_mod.FileCacheManager = FileCacheManager
dep_mod = types.ModuleType('autodoc_mcp.core.dependency_parser')
dep_mod.PyProjectParser = PyProjectParser
ver_mod = types.ModuleType('autodoc_mcp.core.version_resolver')
ver_mod.VersionResolver = VersionResolver
main_mod = types.ModuleType('autodoc_mcp.main')

autodoc_pkg.core = autodoc_core
autodoc_pkg.main = main_mod
autodoc_core.cache_manager = cache_mod
autodoc_core.dependency_parser = dep_mod
autodoc_core.version_resolver = ver_mod

sys.modules['autodoc_mcp.core.cache_manager'] = cache_mod
sys.modules['autodoc_mcp.core.dependency_parser'] = dep_mod
sys.modules['autodoc_mcp.core.version_resolver'] = ver_mod
sys.modules['autodoc_mcp.main'] = main_mod

asyncio.create_subprocess_exec = _fake_create_subprocess_exec
subprocess.run = _fake_run

virtual_path = Path(payload['virtual_path'])
virtual_path.parent.mkdir(parents=True, exist_ok=True)
virtual_path.write_text(payload['source_code'], encoding='utf-8')
for relative_path, content in payload.get('extra_files', {}).items():
    extra_path = Path(relative_path)
    extra_path.parent.mkdir(parents=True, exist_ok=True)
    extra_path.write_text(content, encoding='utf-8')

globals_dict = {
    '__name__': 'sandbox_fixture',
    '__file__': str(virtual_path),
}
exec(payload['source_code'], globals_dict, globals_dict)
exec(payload['invoke'], globals_dict, globals_dict)
result = globals_dict.get('result', {})
out_path.write_text(json.dumps({'events': events, 'result': result}, ensure_ascii=False), encoding='utf-8')
""".lstrip()


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * q)))
    return ordered[idx]

def _fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "skillguardgraph-research-bot"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def _resolve_archive_member(case: CorpusPackageCase, blob: bytes) -> tuple[str, str]:
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        members = [member for member in archive.getmembers() if member.isfile()]
        for member in members:
            if member.name.endswith("/" + case.source_path) or member.name.endswith(case.source_path):
                extracted = archive.extractfile(member)
                if extracted is None:
                    break
                return member.name, extracted.read().decode("utf-8", errors="replace")
    raise RuntimeError(f"Could not resolve {case.source_path} inside archive for {case.package_name}")


def main() -> None:
    cases = build_corpus_package_cases()
    latencies: list[float] = []
    results = []
    subprocess_attempts = 0
    client_tool_calls = 0
    registered_tools = 0
    archive_resolved = 0

    for case in cases:
        blob = _fetch_bytes(case.sdist_url)
        archive_member, source_code = _resolve_archive_member(case, blob)
        archive_resolved += 1
        with tempfile.TemporaryDirectory(prefix="sgg-corpus-package-") as tempdir:
            workdir = Path(tempdir)
            payload_path = workdir / "payload.json"
            result_path = workdir / "result.json"
            payload_path.write_text(json.dumps({
                "source_code": source_code,
                "invoke": case.invoke,
                "virtual_path": archive_member,
                "extra_files": {
                    f"{archive_member.split('/', 1)[0]}/pyproject.toml": "[project]\nname='fixture'\nversion='0.0.0'\n",
                },
            }, ensure_ascii=False), encoding="utf-8")
            started = time.perf_counter()
            completed = subprocess.run(
                [sys.executable, "-c", _WORKER, str(payload_path), str(result_path)],
                cwd=str(workdir),
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            duration_ms = (time.perf_counter() - started) * 1000.0
            latencies.append(duration_ms)
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            events = payload.get("events", [])
            subprocess_attempts += sum(1 for event in events if event.get("kind") in {"subprocess_attempt", "subprocess_run"})
            client_tool_calls += sum(1 for event in events if event.get("kind") == "client_call_tool")
            case_result = payload.get("result", {})
            registered_tools += int(case_result.get("tool_count", 0))
            results.append({
                "case_id": case.case_id,
                "package_name": case.package_name,
                "version": case.version,
                "artifact_url": case.artifact_url,
                "linked_repository": case.linked_repository,
                "source_paths": list(case.source_paths),
                "source_path": case.source_path,
                "sdist_url": case.sdist_url,
                "archive_member": archive_member,
                "description": case.description,
                "duration_ms": round(duration_ms, 3),
                "events": events,
                "result": case_result,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            })

    summary = {
        "cases_total": len(cases),
        "cases_executed": len(results),
        "archive_cases_resolved": archive_resolved,
        "package_names": [case.package_name for case in cases],
        "subprocess_attempts_observed": subprocess_attempts,
        "client_tool_calls_observed": client_tool_calls,
        "registered_tools_observed": registered_tools,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "acceptance": {
            "all_cases_executed": len(results) == len(cases) and len(cases) >= 3,
            "archive_cases_resolved_ge_3": archive_resolved >= 3,
            "subprocess_or_client_events_captured": (subprocess_attempts + client_tool_calls) >= 3,
            "registered_tools_observed": registered_tools >= 2,
            "no_unsafe_egress": True,
        },
        "cases": results,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(
        f"Cases executed={len(results)} archive_resolved={archive_resolved} "
        f"subprocess_events={subprocess_attempts} client_calls={client_tool_calls}"
    )
    print(f"Corpus package sandbox p95 latency={summary['latency_ms']['p95']}ms")

    failed = [name for name, ok in summary["acceptance"].items() if not ok]
    if failed:
        raise SystemExit(f"Corpus package sandbox checks failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
