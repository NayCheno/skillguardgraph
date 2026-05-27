from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from .models import Evidence

WRITE_SCOPES = {"write", "delete", "export", "send", "admin", "modify"}
READ_ONLY_HINTS = {"read-only", "read only", "readonly", "summarize", "summary", "search"}
INSTRUCTION_LIKE_TERMS = {
    "ignore previous",
    "system prompt",
    "hidden instruction",
    "must call",
    "do not tell",
    "secretly",
}


def load_manifest(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _flatten_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _flatten_text(item)
    elif isinstance(value, list):
        for item in value:
            yield from _flatten_text(item)


def analyze_manifest(manifest: Dict[str, Any]) -> List[Evidence]:
    """Convert a skill/tool manifest into normalized evidence.

    The analyzer is deliberately conservative and safe: it does not execute code,
    does not fetch remote URLs, and does not test real credentials.
    """

    name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
    evidence: List[Evidence] = []

    text_blob = "\n".join(_flatten_text(manifest)).lower()
    scopes = {str(s).lower() for s in manifest.get("scopes", [])}
    capability_text_blob = "\n".join(
        _flatten_text({
            "name": manifest.get("name") or manifest.get("id") or "",
            "description": manifest.get("description", ""),
            "schema": manifest.get("schema", {}),
            "parameters": manifest.get("parameters", {}),
            "annotations": manifest.get("annotations", {}),
        })
    ).lower()
    annotations = manifest.get("annotations", {}) or {}

    if any(hint in capability_text_blob for hint in READ_ONLY_HINTS):
        evidence.append(
            Evidence(
                kind="metadata",
                subject=name,
                predicate="declares_capability",
                object="read_only_or_low_risk",
                confidence=0.75,
                attrs={"source": "description/schema"},
            )
        )

    for scope in scopes:
        evidence.append(
            Evidence(
                kind="permission",
                subject=name,
                predicate="requires_scope",
                object=scope,
                confidence=0.95,
                attrs={"source": "manifest.scopes"},
            )
        )

    if scopes & WRITE_SCOPES:
        evidence.append(
            Evidence(
                kind="permission",
                subject=name,
                predicate="requires_high_risk_scope",
                object=",".join(sorted(scopes & WRITE_SCOPES)),
                confidence=0.95,
                attrs={"source": "manifest.scopes"},
            )
        )

    read_only_hint = annotations.get("readOnlyHint")
    if read_only_hint is True:
        evidence.append(
            Evidence(
                kind="metadata",
                subject=name,
                predicate="annotation_claims",
                object="read_only",
                confidence=0.8,
                attrs={"trusted": bool(manifest.get("trusted_server", False))},
            )
        )

    if any(term in text_blob for term in INSTRUCTION_LIKE_TERMS):
        evidence.append(
            Evidence(
                kind="metadata",
                subject=name,
                predicate="contains_instruction_like_text",
                object="manifest_text",
                confidence=0.7,
                attrs={"source": "description/schema"},
            )
        )

    publisher = manifest.get("publisher")
    if publisher:
        evidence.append(
            Evidence(
                kind="governance",
                subject=name,
                predicate="published_by",
                object=str(publisher),
                confidence=0.7,
            )
        )

    if manifest.get("signature"):
        evidence.append(
            Evidence(
                kind="governance",
                subject=name,
                predicate="signed",
                object="true",
                confidence=0.9,
            )
        )
    else:
        evidence.append(
            Evidence(
                kind="governance",
                subject=name,
                predicate="signed",
                object="false",
                confidence=0.8,
            )
        )

    return evidence
