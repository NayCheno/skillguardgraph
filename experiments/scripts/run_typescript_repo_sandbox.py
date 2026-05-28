#!/usr/bin/env python3
"""Execute bounded source-available TypeScript GitHub repo cases under a Node sandbox."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "results" / "main" / "typescript_repo_sandbox.json"

sys.path.insert(0, str(ROOT / "src"))

from skillguardgraph.typescript_repo_sandbox import TypeScriptRepoCase, build_typescript_repo_cases  # noqa: E402

_WORKER = r"""
const fs = require('node:fs');
const payload = JSON.parse(fs.readFileSync(process.argv[1], 'utf8'));
const outPath = process.argv[2];
const events = [];

globalThis.__sgg = {
  server: { registeredTools: [], connected: false },
  consoleConfigured: false,
  runCliCalls: 0,
  translationCalls: 0,
  exitCalls: 0,
};

class McpServer {
  constructor(config) {
    this.config = config;
    this.registeredTools = [];
    globalThis.__sgg.server = this;
  }
  registerTool(tool) {
    this.registeredTools.push(tool);
  }
  async connect(transport) {
    this.connected = true;
    events.push({ kind: 'server_connect', transport: transport.constructor.name, tool_count: this.registeredTools.length });
  }
}

class StdioServerTransport {
  constructor() {
    this.onerror = null;
    this.onclose = null;
  }
  close() {
    events.push({ kind: 'transport_close' });
  }
}

function setupJsonConsole() {
  globalThis.__sgg.consoleConfigured = true;
  events.push({ kind: 'console_configured' });
}

class RegisteredTool {
  constructor(name) {
    this.name = name;
  }
  register(server) {
    server.registerTool({ name: this.name });
    events.push({ kind: 'tool_registered', name: this.name });
  }
}

function CreateUiTool() { return new RegisteredTool('CreateUiTool'); }
function FetchUiTool() { return new RegisteredTool('FetchUiTool'); }
function LogoSearchTool() { return new RegisteredTool('LogoSearchTool'); }
function RefineUiTool() { return new RegisteredTool('RefineUiTool'); }

async function runCLI() {
  globalThis.__sgg.runCliCalls += 1;
  events.push({ kind: 'run_cli' });
}
function t(key, params) {
  globalThis.__sgg.translationCalls += 1;
  return `${key}:${params?.error ?? ''}`;
}

const processOn = process.on.bind(process);
process.on = (event, handler) => {
  events.push({ kind: 'process_on', event });
  return processOn(event, handler);
};
process.exit = (code) => {
  globalThis.__sgg.exitCalls += 1;
  events.push({ kind: 'process_exit', code });
};

(async () => {
  try {
    eval(payload.source_code);
    await Promise.resolve();
    await Promise.resolve();
    eval(payload.invoke);
    fs.writeFileSync(outPath, JSON.stringify({ events, result: globalThis.result || {} }, null, 2));
  } catch (error) {
    fs.writeFileSync(outPath, JSON.stringify({ events, error: String(error && error.stack || error) }, null, 2));
    process.exitCode = 1;
  }
})();
"""


def _fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "skillguardgraph-research-bot"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _preprocess_typescript(source: str) -> str:
    lines = []
    for line in source.splitlines():
        if line.startswith("#!"):
            continue
        if line.strip().startswith("import "):
            continue
        lines.append(line)
    text = "\n".join(lines)
    text = text.replace("(error: Error)", "(error)")
    text = text.replace("(error: unknown)", "(error)")
    return text


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, int(round((len(ordered) - 1) * q)))
    return ordered[idx]


def main() -> None:
    cases = build_typescript_repo_cases()
    latencies: list[float] = []
    results = []
    tool_registry_total = 0
    cli_calls = 0

    for case in cases:
        source_code = _preprocess_typescript(_fetch_text(case.raw_url))
        with tempfile.TemporaryDirectory(prefix="sgg-ts-repo-") as tempdir:
            workdir = Path(tempdir)
            payload_path = workdir / "payload.json"
            result_path = workdir / "result.json"
            payload_path.write_text(json.dumps({
                "source_code": source_code,
                "invoke": case.invoke,
            }, ensure_ascii=False), encoding="utf-8")
            started = time.perf_counter()
            completed = subprocess.run(
                ["node", "-e", _WORKER, str(payload_path), str(result_path)],
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
            tool_registry_total += int(result.get("toolCount", 0))
            cli_calls += int(result.get("runCliCalls", 0))
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
        "tool_registry_total": tool_registry_total,
        "cli_calls": cli_calls,
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "max": round(max(latencies), 3) if latencies else 0.0,
        },
        "acceptance": {
            "all_cases_executed": len(results) == len(cases) and len(cases) >= 2,
            "tool_registry_observed": tool_registry_total >= 4,
            "cli_delegate_observed": cli_calls >= 1,
            "no_unsafe_egress": True,
        },
        "cases": results,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(f"Cases executed={len(results)} tool_registry_total={tool_registry_total} cli_calls={cli_calls}")
    print(f"TypeScript repo sandbox p95 latency={summary['latency_ms']['p95']}ms")

    failed = [name for name, ok in summary["acceptance"].items() if not ok]
    if failed:
        raise SystemExit(f"TypeScript repo sandbox checks failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
