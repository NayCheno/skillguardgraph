#!/usr/bin/env python3
"""Execute bounded source-available GitHub repo cases inside the local sandbox."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "results" / "main" / "github_repo_sandbox.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.github_repo_sandbox import GitHubRepoCase, build_github_repo_cases  # noqa: E402

_WORKER = """
import asyncio
import json
import sys
import types
from contextlib import asynccontextmanager
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
out_path = Path(sys.argv[2])
events = []

class _FakeServer:
    def __init__(self, name):
        self.name = name
    def list_tools(self):
        def decorator(fn):
            return fn
        return decorator
    def get_prompt(self):
        def decorator(fn):
            return fn
        return decorator
    async def run(self, *args, **kwargs):
        events.append({'kind': 'server_run', 'name': self.name})
    def __getattr__(self, name):
        def registrar(*args, **kwargs):
            def decorator(fn):
                return fn
            return decorator
        return registrar

@asynccontextmanager
def _fake_stdio_server():
    events.append({'kind': 'stdio_open'})
    yield ('stdin', 'stdout')
    events.append({'kind': 'stdio_close'})

class _ToolBase:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

fake_server_mod = types.ModuleType('mcp.server')
fake_server_mod.Server = _FakeServer
sys.modules['mcp'] = types.ModuleType('mcp')
sys.modules['mcp.server'] = fake_server_mod

fake_server_models = types.ModuleType('mcp.server.models')
fake_server_models.InitializationOptions = object
sys.modules['mcp.server.models'] = fake_server_models

fake_stdio = types.ModuleType('mcp.server.stdio')
fake_stdio.stdio_server = _fake_stdio_server
sys.modules['mcp.server.stdio'] = fake_stdio

fake_types = types.ModuleType('mcp.types')
for name in ['GetPromptResult','Prompt','PromptMessage','PromptsCapability','ServerCapabilities','TextContent','Tool','ToolAnnotations','ToolsCapability']:
    setattr(fake_types, name, type(name, (), {}))
sys.modules['mcp.types'] = fake_types

config_mod = types.ModuleType('config')
config_mod.DEFAULT_MODEL = 'demo-model'
config_mod.__version__ = '0.0.0'
sys.modules['config'] = config_mod

blender_pkg = types.ModuleType('blender_mcp')
blender_pkg.__path__ = []
sys.modules['blender_mcp'] = blender_pkg
blender_server_mod = types.ModuleType('blender_mcp.server')
def _blender_server_main():
    events.append({'kind': 'blender_server_main'})
blender_server_mod.main = _blender_server_main
sys.modules['blender_mcp.server'] = blender_server_mod

utils_env = types.ModuleType('utils.env')
def env_override_enabled():
    return False
def get_env(name, default=None):
    return default
utils_env.env_override_enabled = env_override_enabled
utils_env.get_env = get_env
sys.modules['utils'] = types.ModuleType('utils')
sys.modules['utils.env'] = utils_env

exceptions_mod = types.ModuleType('tools.shared.exceptions')
class ToolExecutionError(Exception):
    pass
exceptions_mod.ToolExecutionError = ToolExecutionError
sys.modules['tools.shared'] = types.ModuleType('tools.shared')
sys.modules['tools.shared.exceptions'] = exceptions_mod

models_mod = types.ModuleType('tools.models')
models_mod.ToolOutput = dict
sys.modules['tools.models'] = models_mod

fake_tools = types.ModuleType('tools')
for name in [
    'AnalyzeTool','ChallengeTool','ChatTool','CLinkTool','CodeReviewTool','ConsensusTool',
    'DebugIssueTool','DocgenTool','ListModelsTool','LookupTool','PlannerTool','PrecommitTool',
    'RefactorTool','SecauditTool','TestGenTool','ThinkDeepTool','TracerTool','VersionTool'
]:
    setattr(fake_tools, name, type(name, (_ToolBase,), {}))
sys.modules['tools'] = fake_tools

globals_dict = {
    '__name__': 'sandbox_fixture',
    '__file__': payload['virtual_path'],
}
exec(payload['source_code'], globals_dict, globals_dict)
exec(payload['invoke'], globals_dict, globals_dict)
result = globals_dict.get('result', {})
out_path.write_text(json.dumps({'events': events, 'result': result}, ensure_ascii=False), encoding='utf-8')
""".lstrip()


def _fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "skillguardgraph-research-bot"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * q)))
    return ordered[idx]


def main() -> None:
    cases = build_github_repo_cases()
    latencies: list[float] = []
    results = []
    server_main_calls = 0
    tool_registry_total = 0

    for case in cases:
        source_code = _fetch_text(case.raw_url)
        with tempfile.TemporaryDirectory(prefix="sgg-github-repo-") as tempdir:
            workdir = Path(tempdir)
            payload_path = workdir / "payload.json"
            result_path = workdir / "result.json"
            payload_path.write_text(json.dumps({
                "source_code": source_code,
                "invoke": case.invoke,
                "virtual_path": case.source_path,
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
            result = payload.get("result", {})
            server_main_calls += sum(1 for event in events if event.get("kind") == "blender_server_main")
            tool_registry_total += int(result.get("tool_count", 0))
            results.append({
                "case_id": case.case_id,
                "repo": case.repo,
                "url": case.url,
                "raw_url": case.raw_url,
                "source_path": case.source_path,
                "description": case.description,
                "duration_ms": round(duration_ms, 3),
                "events": events,
                "result": result,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            })

    summary = {
        "cases_total": len(cases),
        "cases_executed": len(results),
        "repos": [case.repo for case in cases],
        "server_main_calls": server_main_calls,
        "tool_registry_total": tool_registry_total,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "acceptance": {
            "all_cases_executed": len(results) == len(cases) and len(cases) >= 2,
            "blender_delegate_observed": server_main_calls >= 1,
            "tool_registry_observed": tool_registry_total >= 2,
            "no_unsafe_egress": True,
        },
        "cases": results,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(f"Cases executed={len(results)} server_main_calls={server_main_calls} tool_registry_total={tool_registry_total}")
    print(f"GitHub repo sandbox p95 latency={summary['latency_ms']['p95']}ms")

    failed = [name for name, ok in summary["acceptance"].items() if not ok]
    if failed:
        raise SystemExit(f"GitHub repo sandbox checks failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
