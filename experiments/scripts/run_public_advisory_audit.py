#!/usr/bin/env python3
"""Cross-check the real public corpus against known public MCP advisories."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_PATH = ROOT / "results" / "ecosystem" / "real_ecosystem_samples.jsonl"
OUT_PATH = ROOT / "results" / "ecosystem" / "public_advisory_audit.json"


@dataclass(frozen=True)
class AdvisoryCase:
    advisory_id: str
    cve_id: str
    package_name: str | None
    repository_url: str | None
    ecosystem: str
    summary: str
    severity: str
    published_at: str
    affected_gte: str | None
    affected_lt: str | None
    fixed_version: str | None
    source_urls: tuple[str, ...]

ADVISORIES: tuple[AdvisoryCase, ...] = (
    AdvisoryCase(
        advisory_id="GHSA-345p-7cg4-v4c7",
        cve_id="CVE-2026-25536",
        package_name="@modelcontextprotocol/sdk",
        repository_url="https://github.com/modelcontextprotocol/typescript-sdk",
        ecosystem="npm",
        summary="Cross-client data leak via shared server/transport instance reuse in the official TypeScript SDK.",
        severity="moderate",
        published_at="2026-02-04",
        affected_gte="1.10.0",
        affected_lt="1.26.0",
        fixed_version="1.26.0",
        source_urls=(
            "https://github.com/advisories/GHSA-345p-7cg4-v4c7",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-25536",
        ),
    ),
    AdvisoryCase(
        advisory_id="GHSA-vjqx-cfc4-9h6v",
        cve_id="CVE-2026-27735",
        package_name="@modelcontextprotocol/server-git",
        repository_url="https://github.com/modelcontextprotocol/servers",
        ecosystem="github",
        summary="Path traversal in git_add allows staging files outside repository boundaries in the official git reference server.",
        severity="moderate",
        published_at="2026-02-25",
        affected_gte=None,
        affected_lt="2026.1.14",
        fixed_version="2026.1.14",
        source_urls=(
            "https://github.com/advisories/GHSA-vjqx-cfc4-9h6v",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-27735",
        ),
    ),
)


def _normalize_repo_url(url: str | None) -> str | None:
    if not url:
        return None
    value = str(url).strip()
    value = value.replace("git+", "")
    value = re.sub(r"\.git$", "", value)
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value.split(":", 1)[1]
    return value.rstrip("/")


def _version_key(version: str) -> tuple[Any, ...]:
    parts: list[Any] = []
    for chunk in re.split(r"[^0-9A-Za-z]+", version):
        if not chunk:
            continue
        parts.append(int(chunk) if chunk.isdigit() else chunk.lower())
    return tuple(parts)


def _version_in_range(version: str, advisory: AdvisoryCase) -> bool:
    current = _version_key(version)
    if advisory.affected_gte and current < _version_key(advisory.affected_gte):
        return False
    if advisory.affected_lt and current >= _version_key(advisory.affected_lt):
        return False
    return True


def _iter_samples() -> Iterable[dict[str, Any]]:
    for line in SAMPLES_PATH.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def _sample_matches(sample: dict[str, Any], advisory: AdvisoryCase) -> bool:
    names = {
        str(sample.get("repo") or ""),
        str(sample.get("dedup_key") or ""),
        str((sample.get("manifest") or {}).get("name") or ""),
    }
    if advisory.package_name:
        return advisory.package_name in names

    repos = {
        _normalize_repo_url(sample.get("linked_repository")),
        _normalize_repo_url((sample.get("manifest") or {}).get("repository")),
        _normalize_repo_url(sample.get("url")),
    }
    repos.discard(None)
    return bool(advisory.repository_url and _normalize_repo_url(advisory.repository_url) in repos)


def build_advisory_audit() -> dict[str, Any]:
    samples = list(_iter_samples())
    cases: list[dict[str, Any]] = []
    present_count = 0
    vulnerable_count = 0
    patched_count = 0

    for advisory in ADVISORIES:
        matched_samples = [sample for sample in samples if _sample_matches(sample, advisory)]
        status = "not_in_corpus"
        case_matches: list[dict[str, Any]] = []
        for sample in matched_samples:
            version = str(sample.get("package_version") or (sample.get("manifest") or {}).get("version") or "")
            if version and (advisory.affected_gte or advisory.affected_lt):
                vulnerable = _version_in_range(version, advisory)
                if vulnerable:
                    status = "present_vulnerable"
                    vulnerable_count += 1
                else:
                    if status != "present_vulnerable":
                        status = "present_patched"
                    patched_count += 1
            else:
                if status == "not_in_corpus":
                    status = "present_no_version"
            case_matches.append({
                "repo": sample.get("repo"),
                "url": sample.get("url"),
                "source": sample.get("source"),
                "package_version": version or None,
                "linked_repository": sample.get("linked_repository"),
                "policy_risk": sample.get("policy_risk"),
                "code_availability": sample.get("code_availability"),
            })
        if matched_samples:
            present_count += 1
        cases.append({
            "advisory_id": advisory.advisory_id,
            "cve_id": advisory.cve_id,
            "ecosystem": advisory.ecosystem,
            "package_name": advisory.package_name,
            "repository_url": advisory.repository_url,
            "summary": advisory.summary,
            "severity": advisory.severity,
            "published_at": advisory.published_at,
            "affected_gte": advisory.affected_gte,
            "affected_lt": advisory.affected_lt,
            "fixed_version": advisory.fixed_version,
            "source_urls": list(advisory.source_urls),
            "status": status,
            "matches": case_matches,
        })

    return {
        "advisories_total": len(ADVISORIES),
        "advisories_present_in_corpus": present_count,
        "currently_vulnerable_matches": vulnerable_count,
        "patched_or_unaffected_matches": patched_count,
        "cases": cases,
        "notes": [
            "This audit matches checked-in public-corpus artifacts against known public MCP advisories.",
            "A match does not imply the current measured version is vulnerable; status is version-aware when package metadata is present.",
            "This audit does not replace disclosure-backed validation of new findings from the passive crawl.",
        ],
    }


def main() -> None:
    payload = build_advisory_audit()
    OUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Results written to {OUT_PATH}")
    print(
        "Advisories present="
        f"{payload['advisories_present_in_corpus']} vulnerable_matches={payload['currently_vulnerable_matches']} "
        f"patched_or_unaffected={payload['patched_or_unaffected_matches']}"
    )


if __name__ == "__main__":
    main()
