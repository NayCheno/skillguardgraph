#!/usr/bin/env python3
"""Probe a bounded set of public remote MCP endpoints from the checked-in corpus."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_PATH = ROOT / "results" / "ecosystem" / "real_ecosystem_samples.jsonl"
OUT_PATH = ROOT / "results" / "main" / "remote_endpoint_audit.json"

INIT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-06-18",
    "Origin": "https://modelcontextprotocol.io",
    "User-Agent": "skillguardgraph-research-bot",
}


@dataclass(frozen=True)
class RemoteEndpointProfile:
    case_id: str
    repo: str
    description: str
    expected_class: str


PROFILES: tuple[RemoteEndpointProfile, ...] = (
    RemoteEndpointProfile(
        case_id="public_tools_aarna",
        repo="ai.aarna/atars-mcp",
        description="Public official-registry endpoint expected to complete initialize plus tools/list over SSE.",
        expected_class="public_tools",
    ),
    RemoteEndpointProfile(
        case_id="public_tools_agenticshelf",
        repo="ai.agenticshelf/mcp",
        description="Public official-registry endpoint expected to complete initialize plus tools/list over JSON.",
        expected_class="public_tools",
    ),
    RemoteEndpointProfile(
        case_id="protected_auth_inference",
        repo="ac.inference.sh/mcp",
        description="Public official-registry endpoint expected to require authentication before MCP use.",
        expected_class="auth_required",
    ),
    RemoteEndpointProfile(
        case_id="protected_origin_tandem",
        repo="ac.tandem/docs-mcp",
        description="Public official-registry endpoint expected to reject unapproved Origin headers.",
        expected_class="origin_protected",
    ),
)


def _load_samples() -> dict[str, dict[str, Any]]:
    samples: dict[str, dict[str, Any]] = {}
    for line in SAMPLES_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        sample = json.loads(line)
        samples[str(sample.get("repo") or "")] = sample
    return samples


def _first_remote_url(sample: dict[str, Any]) -> str | None:
    remotes = sample.get("official_registry_remotes") or []
    for remote in remotes:
        url = str(remote.get("url") or "")
        if url.startswith("https://"):
            return url
    return None


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


def _post_json(url: str, payload: dict[str, Any], session_id: str | None = None) -> tuple[int, dict[str, str], str]:
    headers = dict(INIT_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status, {k: v for k, v in resp.headers.items()}, resp.read().decode("utf-8", errors="replace")


def _classify_http_error(code: int, body: str) -> str:
    lowered = body.lower()
    if code == 401 or "auth" in lowered or "token" in lowered or "unauthorized" in lowered:
        return "auth_required"
    if code == 403 or "origin" in lowered or "forbidden_origin" in lowered:
        return "origin_protected"
    return f"http_{code}"


def _initialized_notification(url: str, session_id: str | None) -> int:
    payload = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    status, _, _ = _post_json(url, payload, session_id=session_id)
    return status


def _tools_list(url: str, session_id: str | None) -> tuple[str, int]:
    payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    status, _, body = _post_json(url, payload, session_id=session_id)
    parsed = _parse_mcp_http_body(body)
    result = parsed.get("result") or {}
    tools = result.get("tools") or []
    return ("tools_list_success" if isinstance(tools, list) else "tools_list_unparsed", len(tools) if isinstance(tools, list) else 0)


def build_remote_cases() -> list[dict[str, Any]]:
    samples = _load_samples()
    cases: list[dict[str, Any]] = []
    for profile in PROFILES:
        sample = samples.get(profile.repo)
        if not sample:
            continue
        url = _first_remote_url(sample)
        if not url:
            continue
        outcome = {
            "initialize_status": "unattempted",
            "initialized_notification_status": None,
            "tools_list_status": None,
            "tool_count": 0,
            "session_id_present": False,
            "http_status": None,
            "notes": [],
        }
        try:
            status, headers, body = _post_json(
                url,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "skillguardgraph", "version": "0.1.0"},
                    },
                },
            )
            parsed = _parse_mcp_http_body(body)
            session_id = headers.get("Mcp-Session-Id")
            outcome["http_status"] = status
            outcome["session_id_present"] = bool(session_id)
            if status == 200 and parsed.get("result"):
                outcome["initialize_status"] = "initialize_success"
                try:
                    outcome["initialized_notification_status"] = _initialized_notification(url, session_id)
                except urllib.error.HTTPError as exc:
                    outcome["initialized_notification_status"] = exc.code
                    outcome["notes"].append(f"initialized_notification_http_{exc.code}")
                except Exception as exc:
                    outcome["notes"].append(f"initialized_notification_error:{type(exc).__name__}")
                try:
                    tools_status, tool_count = _tools_list(url, session_id)
                    outcome["tools_list_status"] = tools_status
                    outcome["tool_count"] = tool_count
                except urllib.error.HTTPError as exc:
                    outcome["tools_list_status"] = _classify_http_error(exc.code, exc.read().decode("utf-8", errors="replace"))
                except Exception as exc:
                    outcome["tools_list_status"] = f"error:{type(exc).__name__}"
            else:
                outcome["initialize_status"] = f"unexpected_{status}"
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            outcome["http_status"] = exc.code
            outcome["initialize_status"] = _classify_http_error(exc.code, body)
        except Exception as exc:
            outcome["initialize_status"] = f"transport_error:{type(exc).__name__}"

        cases.append({
            "case_id": profile.case_id,
            "repo": profile.repo,
            "url": url,
            "source": sample.get("source"),
            "description": profile.description,
            "expected_class": profile.expected_class,
            **outcome,
        })
    return cases


def main() -> None:
    cases = build_remote_cases()
    public_tools = sum(1 for case in cases if case.get("tools_list_status") == "tools_list_success" and int(case.get("tool_count", 0)) >= 1)
    protected = sum(1 for case in cases if case.get("initialize_status") in {"auth_required", "origin_protected"})
    payload = {
        "cases_total": len(cases),
        "cases_probed": len(cases),
        "initialize_successes": sum(1 for case in cases if case.get("initialize_status") == "initialize_success"),
        "tools_list_successes": public_tools,
        "protected_endpoints_observed": protected,
        "acceptance": {
            "all_cases_probed": len(cases) == len(PROFILES),
            "initialize_success_ge_2": sum(1 for case in cases if case.get("initialize_status") == "initialize_success") >= 2,
            "tools_list_success_ge_1": public_tools >= 1,
            "protected_endpoint_observed": protected >= 1,
        },
        "cases": cases,
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(
        f"Initialize successes={payload['initialize_successes']} tools_list_successes={payload['tools_list_successes']} "
        f"protected_endpoints={payload['protected_endpoints_observed']}"
    )
    failed = [name for name, ok in payload["acceptance"].items() if not ok]
    if failed:
        raise SystemExit(f"Remote endpoint audit checks failed: {', '.join(failed)}")


if __name__ == "__main__":
    main()
