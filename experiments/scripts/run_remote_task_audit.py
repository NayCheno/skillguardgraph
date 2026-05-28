#!/usr/bin/env python3
"""Execute bounded harmless MCP tool calls against public remote endpoints."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "results" / "main" / "remote_task_audit.json"

BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-06-18",
    "Origin": "https://modelcontextprotocol.io",
    "User-Agent": "skillguardgraph-research-bot",
}


@dataclass(frozen=True)
class RemoteTaskCase:
    case_id: str
    repo: str
    url: str
    tool_name: str
    arguments: dict[str, Any]
    expected_signal: str
    description: str


CASES: tuple[RemoteTaskCase, ...] = (
    RemoteTaskCase(
        case_id="aarna_available_symbols",
        repo="ai.aarna/atars-mcp",
        url="https://mcp.aarna.ai/mcp",
        tool_name="get_available_symbols",
        arguments={},
        expected_signal="available_symbols",
        description="Read-only tool call expected to return the list of supported crypto symbols.",
    ),
    RemoteTaskCase(
        case_id="agenticshelf_list_products",
        repo="ai.agenticshelf/mcp",
        url="https://api.agenticshelf.ai/mcp",
        tool_name="list_products",
        arguments={},
        expected_signal="commerce_unavailable",
        description="Read-only tool call expected to return a structured placeholder when the commerce backend is absent.",
    ),
)


def _parse_mcp_http_body(text: str) -> dict[str, Any]:
    body = text.strip()
    if not body:
        return {}
    if body.startswith("{"):
        return json.loads(body)
    data_lines: list[str] = []
    for line in body.splitlines():
        if line.startswith("data: "):
            data_lines.append(line[6:])
    if data_lines:
        return json.loads("".join(data_lines))
    return {"raw": body}


def _post(url: str, payload: dict[str, Any], session_id: str | None = None) -> tuple[int, dict[str, str], str]:
    headers = dict(BASE_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
    with urllib.request.urlopen(req, timeout=40) as resp:
        return resp.status, {k: v for k, v in resp.headers.items()}, resp.read().decode("utf-8", errors="replace")


def _initialize(url: str) -> tuple[str | None, dict[str, Any]]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "skillguardgraph", "version": "0.1.0"},
        },
    }
    _, headers, body = _post(url, payload)
    return headers.get("Mcp-Session-Id"), _parse_mcp_http_body(body)


def _initialized(url: str, session_id: str | None) -> int:
    status, _, _ = _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id=session_id)
    return status


def _call_tool(url: str, session_id: str | None, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    _, _, body = _post(url, payload, session_id=session_id)
    return _parse_mcp_http_body(body)


def _extract_signal(result: dict[str, Any]) -> tuple[str, str]:
    result_body = (result.get("result") or {}) if isinstance(result, dict) else {}
    structured = result_body.get("structuredContent") or {}
    content = result_body.get("content") or []
    text_blob = ""
    if content and isinstance(content, list):
        first = content[0] or {}
        if isinstance(first, dict):
            text_blob = str(first.get("text") or "")
    if structured:
        return json.dumps(structured, ensure_ascii=False), text_blob
    return text_blob, text_blob


def build_remote_task_audit() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    successful_calls = 0
    structured_calls = 0

    for case in CASES:
        record = {
            "case_id": case.case_id,
            "repo": case.repo,
            "url": case.url,
            "tool_name": case.tool_name,
            "arguments": case.arguments,
            "expected_signal": case.expected_signal,
            "description": case.description,
            "initialized_notification_status": None,
            "session_id_present": False,
            "tool_call_success": False,
            "signal_matched": False,
            "structured_result": False,
            "tool_result_preview": None,
        }
        try:
            session_id, init_result = _initialize(case.url)
            record["session_id_present"] = bool(session_id)
            record["initialized_notification_status"] = _initialized(case.url, session_id)
            tool_result = _call_tool(case.url, session_id, case.tool_name, case.arguments)
            signal_source, preview = _extract_signal(tool_result)
            record["tool_result_preview"] = preview[:500]
            record["tool_call_success"] = not bool((tool_result.get("result") or {}).get("isError"))
            record["signal_matched"] = case.expected_signal in signal_source
            record["structured_result"] = bool((tool_result.get("result") or {}).get("structuredContent"))
            if record["tool_call_success"]:
                successful_calls += 1
            if record["structured_result"]:
                structured_calls += 1
        except urllib.error.HTTPError as exc:
            record["http_error"] = exc.code
            record["error_preview"] = exc.read().decode("utf-8", errors="replace")[:500]
        except Exception as exc:
            record["error_type"] = type(exc).__name__
            record["error_message"] = str(exc)
        cases.append(record)

    return {
        "cases_total": len(CASES),
        "cases_executed": len(cases),
        "successful_tool_calls": successful_calls,
        "structured_tool_results": structured_calls,
        "acceptance": {
            "all_cases_executed": len(cases) == len(CASES),
            "successful_tool_calls_ge_2": successful_calls >= 2,
            "all_signals_matched": all(case.get("signal_matched") for case in cases),
            "structured_result_observed": structured_calls >= 1,
        },
        "cases": cases,
    }


def main() -> None:
    payload = build_remote_task_audit()
    OUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(
        f"Cases executed={payload['cases_executed']} successful_tool_calls={payload['successful_tool_calls']} "
        f"structured_results={payload['structured_tool_results']}"
    )
    failed = [name for name, ok in payload["acceptance"].items() if not ok]
    if failed:
        raise SystemExit(f"Remote task audit checks failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
