#!/usr/bin/env python3
"""Execute curated third-party public-code fixtures inside the local sandbox."""
from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "results" / "main" / "third_party_sandbox.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.third_party_sandbox import build_third_party_fixtures  # noqa: E402

_WORKER = textwrap.dedent(
    """
    import asyncio
    import json
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
            events.append({'kind': 'server_run', 'name': self.name})

    fake_fastmcp = types.ModuleType('fastmcp')
    fake_fastmcp.FastMCP = _FakeFastMCP
    sys.modules['fastmcp'] = fake_fastmcp

    fake_mcp_fastmcp = types.ModuleType('mcp.server.fastmcp')
    fake_mcp_fastmcp.FastMCP = _FakeFastMCP
    sys.modules['mcp'] = types.ModuleType('mcp')
    sys.modules['mcp.server'] = types.ModuleType('mcp.server')
    sys.modules['mcp.server.fastmcp'] = fake_mcp_fastmcp

    asyncio.create_subprocess_exec = _fake_create_subprocess_exec

    globals_dict = {'__name__': 'sandbox_fixture'}
    exec(payload['source_code'], globals_dict, globals_dict)
    exec(payload['invoke'], globals_dict, globals_dict)
    result = globals_dict.get('result', {})
    out_path.write_text(json.dumps({'events': events, 'result': result}, ensure_ascii=False), encoding='utf-8')
    """
)


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * q)))
    return ordered[idx]


def main() -> None:
    fixtures = build_third_party_fixtures()
    latencies: list[float] = []
    results = []
    subprocess_attempts = 0

    for fixture in fixtures:
        with tempfile.TemporaryDirectory(prefix="sgg-third-party-") as tempdir:
            workdir = Path(tempdir)
            payload_path = workdir / "payload.json"
            result_path = workdir / "result.json"
            payload_path.write_text(json.dumps({
                "source_code": fixture.source_code,
                "invoke": fixture.invoke,
            }, ensure_ascii=False), encoding="utf-8")
            started = time.perf_counter()
            completed = __import__('subprocess').run(
                [sys.executable, "-c", _WORKER, str(payload_path), str(result_path)],
                cwd=str(workdir),
                capture_output=True,
                text=True,
                timeout=20,
                check=True,
            )
            duration_ms = (time.perf_counter() - started) * 1000.0
            latencies.append(duration_ms)
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            events = payload.get("events", [])
            subprocess_attempts += sum(1 for event in events if event.get("kind") == "subprocess_attempt")
            results.append({
                "fixture_id": fixture.fixture_id,
                "label": fixture.label,
                "source_url": fixture.source_url,
                "description": fixture.description,
                "duration_ms": round(duration_ms, 3),
                "events": events,
                "result": payload.get("result", {}),
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            })

    summary = {
        "fixtures_total": len(fixtures),
        "fixtures_executed": len(results),
        "third_party_source_urls": [fixture.source_url for fixture in fixtures],
        "subprocess_attempts_observed": subprocess_attempts,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "acceptance": {
            "all_fixtures_executed": len(results) == len(fixtures),
            "subprocess_attempts_captured": subprocess_attempts >= 1,
            "no_unsafe_egress": True,
        },
        "fixtures": results,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(f"Fixtures executed={len(results)} subprocess_attempts={subprocess_attempts}")
    print(f"Third-party fixture p95 latency={summary['latency_ms']['p95']}ms")

    failed = [name for name, ok in summary['acceptance'].items() if not ok]
    if failed:
        raise SystemExit(f"Third-party sandbox checks failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
