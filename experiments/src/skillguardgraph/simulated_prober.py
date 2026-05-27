"""Sandbox prober for the SkillGuardGraph evidence fusion system.

Performs safe, simulated sandbox probing of skill manifests and source code
to identify capability mismatches, destructive annotations, and open-world
access patterns. Does NOT execute any untrusted code.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List

from .models import Evidence


@dataclass
class SandboxObservation:
    skill: str
    behavior: str
    target: str
    confidence: float = 0.8


def observations_to_evidence(observations: List[SandboxObservation]) -> List[Evidence]:
    """Convert safe sandbox observations into evidence.

    This module is a placeholder. A real implementation should only run in an
    isolated environment with fake credentials, synthetic data, and blocked or
    sinkholed egress.
    """

    evidence: List[Evidence] = []
    for obs in observations:
        evidence.append(
            Evidence(
                kind="sandbox",
                subject=obs.skill,
                predicate="observes_behavior",
                object=obs.behavior,
                confidence=obs.confidence,
                attrs={"target": obs.target},
            )
        )
    return evidence


# ---------------------------------------------------------------------------
# Pattern constants for source-code probing
# ---------------------------------------------------------------------------

_NETWORK_PATTERNS = [
    re.compile(r"\brequests\.(post|put|patch|delete)\b"),
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\burllib\.request\b"),
    re.compile(r"\bhttpx\.(post|put|patch|delete)\b"),
    re.compile(r"\bsocket\.(connect|send)\b"),
]

_FILE_WRITE_PATTERNS = [
    re.compile(r"""open\s*\([^)]*['"][wa]"""),
    re.compile(r"\bos\.remove\b"),
    re.compile(r"\bshutil\.rmtree\b"),
]

_SHELL_PATTERNS = [
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bos\.system\b"),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\bshell=True\b"),
]

_OPEN_WORLD_INDICATORS = [
    re.compile(r"https?://[^\s'\"]+"),
    re.compile(r"\brequests\.get\s*\("),
    re.compile(r"\bfetch\s*\(\s*['\"]https?://"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def probe_skill(
    skill_name: str,
    manifest: Dict[str, Any],
    source_code: str | None = None,
) -> List[SandboxObservation]:
    """Simulate sandbox probing by analyzing manifest and source code.

    Returns SandboxObservation objects that capture security-relevant
    behaviors detected through static analysis of the manifest metadata
    and (optional) source code patterns.
    """
    observations: List[SandboxObservation] = []
    annotations = manifest.get("annotations", {}) or {}

    # 1. Destructive capability hint in annotations
    if annotations.get("destructiveHint") is True:
        observations.append(
            SandboxObservation(
                skill=skill_name,
                behavior="destructive_annotation_present",
                target="manifest.annotations.destructiveHint",
                confidence=0.9,
            )
        )

    # 2. Source code analysis (when available)
    if source_code and source_code.strip():
        _probe_source_code(skill_name, source_code, observations)

    # 3. Read-only hint with write-capable source code mismatch
    read_only_hint = annotations.get("readOnlyHint") is True
    has_write_code = _has_any_pattern(source_code, _FILE_WRITE_PATTERNS + _SHELL_PATTERNS)
    if read_only_hint and has_write_code:
        observations.append(
            SandboxObservation(
                skill=skill_name,
                behavior="readonly_hint_with_write_code",
                target="source_code",
                confidence=0.85,
            )
        )

    # 4. Open-world network access patterns
    if source_code and _has_any_pattern(source_code, _OPEN_WORLD_INDICATORS):
        observations.append(
            SandboxObservation(
                skill=skill_name,
                behavior="open_world_network_access",
                target="source_code",
                confidence=0.8,
            )
        )

    # 5. Benign baseline: no issues detected
    if not observations:
        observations.append(
            SandboxObservation(
                skill=skill_name,
                behavior="no_suspicious_behavior",
                target="manifest+source",
                confidence=0.7,
            )
        )

    return observations


def probe_skill_as_evidence(
    skill_name: str,
    manifest: Dict[str, Any],
    source_code: str | None = None,
) -> List[Evidence]:
    """Probe a skill and return evidence items directly.

    Convenience wrapper that calls probe_skill then converts to Evidence.
    """
    observations = probe_skill(skill_name, manifest, source_code)
    return observations_to_evidence(observations)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _has_any_pattern(text: str | None, patterns: List[re.Pattern[str]]) -> bool:
    if not text:
        return False
    return any(p.search(text) for p in patterns)


def _probe_source_code(
    skill_name: str,
    source_code: str,
    observations: List[SandboxObservation],
) -> None:
    """Check source code for security-relevant operations."""
    if _has_any_pattern(source_code, _NETWORK_PATTERNS):
        observations.append(
            SandboxObservation(
                skill=skill_name,
                behavior="network_operation_detected",
                target="source_code",
                confidence=0.85,
            )
        )

    if _has_any_pattern(source_code, _FILE_WRITE_PATTERNS):
        observations.append(
            SandboxObservation(
                skill=skill_name,
                behavior="file_write_operation_detected",
                target="source_code",
                confidence=0.85,
            )
        )

    if _has_any_pattern(source_code, _SHELL_PATTERNS):
        observations.append(
            SandboxObservation(
                skill=skill_name,
                behavior="shell_exec_operation_detected",
                target="source_code",
                confidence=0.9,
            )
        )

