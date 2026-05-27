"""Lightweight rule-based static analyzer for skill source code.

Scans source code strings for common patterns that indicate security-relevant
capabilities (sources, sinks, privilege escalation) without executing the code.
Designed for the SkillGuardGraph evidence fusion pipeline.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from .models import Evidence


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Network sinks: outbound data transfer
_NETWORK_SINK_PATTERNS = [
    re.compile(r"\brequests\.(post|put|patch|delete)\b"),
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\bhttp\.client\b"),
    re.compile(r"\burllib\.request\b"),
    re.compile(r"\bhttpx\.(post|put|patch|delete)\b"),
    re.compile(r"\baiohttp\.ClientSession\b"),
    re.compile(r"\bsocket\.(connect|send)\b"),
    re.compile(r"\bxmlrpc\.client\b"),
]

# File write / delete sinks
_FILE_WRITE_PATTERNS = [
    re.compile(r"""open\s*\([^)]*['"][wa]"""),
    re.compile(r"\bos\.remove\b"),
    re.compile(r"\bos\.unlink\b"),
    re.compile(r"\bshutil\.rmtree\b"),
    re.compile(r"\bshutil\.move\b"),
    re.compile(r"\bos\.rename\b"),
    re.compile(r"\bpathlib\.Path\([^)]*\)\.write_"),
    re.compile(r"\bPath\([^)]*\)\.write_"),
]

# Shell / exec sinks
_SHELL_PATTERNS = [
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bos\.system\b"),
    re.compile(r"\bos\.popen\b"),
    re.compile(r"\bexec\s*\("),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bshell=True\b"),
]

# Email / message sinks
_EMAIL_PATTERNS = [
    re.compile(r"\bsmtplib\b"),
    re.compile(r"\bsend_message\b"),
    re.compile(r"\bsendmail\b"),
    re.compile(r"\bemail\.mime\b"),
]

# Env / token / credential sources
_ENV_SOURCE_PATTERNS = [
    re.compile(r"\bos\.environ\b"),
    re.compile(r"\bos\.getenv\b"),
    re.compile(r"\bprocess\.env\b"),
    re.compile(r"\bdotenv\b"),
    re.compile(r"\bconfigparser\b"),
]

# File read source
_FILE_READ_PATTERNS = [
    re.compile(r"""open\s*\([^)]*['"][r]"""),
    re.compile(r"\bPath\([^)]*\)\.read_"),
    re.compile(r"\bpathlib\.Path\([^)]*\)\.read_"),
    re.compile(r"\bios\.listdir\b"),
    re.compile(r"\bglob\.glob\b"),
]

# User input source
_USER_INPUT_PATTERNS = [
    re.compile(r"\binput\s*\("),
    re.compile(r"\bjson\.loads\s*\(\s*request"),
    re.compile(r"\brequest\.(body|form|args|json)\b"),
    re.compile(r"\bsys\.stdin\b"),
    re.compile(r"\bsys\.argv\b"),
    re.compile(r"\bgetpass\b"),
]
_DB_PATTERNS = [
    re.compile(r"\bcursor\.execute\b"),
    re.compile(r"\bSELECT\b.*\bFROM\b", re.IGNORECASE),
    re.compile(r"\bcollection\.find\b"),
    re.compile(r"\bsession\.query\b"),
]

# Memory / config write
_MEMORY_WRITE_PATTERNS = [
    re.compile(r"\bmemory\.store\b"),
    re.compile(r"\bconfig\["),
    re.compile(r"\bupdate_config\b"),
    re.compile(r"\bset_config\b"),
    re.compile(r"\bsave_state\b"),
]

# Credential access indicators
_CREDENTIAL_PATTERNS = [
    re.compile(r"\boauth\b", re.IGNORECASE),
    re.compile(r"\btoken\b.*\bauth\b", re.IGNORECASE),
    re.compile(r"\bapi_key\b", re.IGNORECASE),
    re.compile(r"\bapi_secret\b", re.IGNORECASE),
    re.compile(r"\bcredential", re.IGNORECASE),
    re.compile(r"\bpassword\b", re.IGNORECASE),
    re.compile(r"\bjwt\b", re.IGNORECASE),
]

# PII / confidential data indicators
_PII_PATTERNS = [
    re.compile(r"\bssn\b", re.IGNORECASE),
    re.compile(r"\bsocial.security\b", re.IGNORECASE),
    re.compile(r"\bcredit.card\b", re.IGNORECASE),
    re.compile(r"\bemail.address\b", re.IGNORECASE),
    re.compile(r"\bpersonal.data\b", re.IGNORECASE),
    re.compile(r"\bconfidential\b", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Pattern group → (predicate, object, kind) mapping
# ---------------------------------------------------------------------------

_SINK_GROUPS: List[tuple[List[re.Pattern[str]], str, str]] = [
    (_NETWORK_SINK_PATTERNS, "sink_identified", "network_send"),
    (_FILE_WRITE_PATTERNS, "sink_identified", "file_write"),
    (_SHELL_PATTERNS, "sink_identified", "shell_exec"),
    (_EMAIL_PATTERNS, "sink_identified", "email_send"),
    (_MEMORY_WRITE_PATTERNS, "sink_identified", "memory_write"),
]

_SOURCE_GROUPS: List[tuple[List[re.Pattern[str]], str, str]] = [
    (_ENV_SOURCE_PATTERNS, "source_identified", "env_var"),
    (_FILE_READ_PATTERNS, "source_identified", "file_read"),
    (_USER_INPUT_PATTERNS, "source_identified", "user_input"),
    (_DB_PATTERNS, "source_identified", "database_query"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _any_match(patterns: List[re.Pattern[str]], text: str) -> bool:
    return any(p.search(text) for p in patterns)


def _matching_pattern_texts(patterns: List[re.Pattern[str]], text: str) -> List[str]:
    """Return the first matched substring for each pattern that fires."""
    seen: set[str] = set()
    out: List[str] = []
    for p in patterns:
        m = p.search(text)
        if m and m.group() not in seen:
            seen.add(m.group())
            out.append(m.group())
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_source(skill_name: str, source_code: str) -> List[Evidence]:
    """Analyze source code text and produce evidence items.

    This is a lightweight rule-based scanner. It does not execute code,
    perform taint tracking, or invoke external SAST tools.
    """
    if not source_code or not source_code.strip():
        return []

    evidence: List[Evidence] = []
    code = source_code

    # --- Sinks ---
    detected_sinks: set[str] = set()
    for patterns, predicate, obj in _SINK_GROUPS:
        if _any_match(patterns, code):
            detected_sinks.add(obj)
            matches = _matching_pattern_texts(patterns, code)
            evidence.append(
                Evidence(
                    kind="static",
                    subject=skill_name,
                    predicate=predicate,
                    object=obj,
                    confidence=0.85,
                    attrs={"matches": matches[:5]},
                )
            )

    # --- Sources ---
    detected_sources: set[str] = set()
    for patterns, predicate, obj in _SOURCE_GROUPS:
        if _any_match(patterns, code):
            detected_sources.add(obj)
            matches = _matching_pattern_texts(patterns, code)
            evidence.append(
                Evidence(
                    kind="static",
                    subject=skill_name,
                    predicate=predicate,
                    object=obj,
                    confidence=0.85,
                    attrs={"matches": matches[:5]},
                )
            )

    # --- Untrusted source label ---
    if "user_input" in detected_sources or "env_var" in detected_sources:
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="has_source_label",
                object="untrusted",
                confidence=0.8,
                attrs={"reason": "external_input_detected"},
            )
        )

    # --- External sink flag ---
    external_sinks = detected_sources & set()  # will use detected sinks
    if "network_send" in detected_sinks or "email_send" in detected_sinks:
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="is_external_sink",
                object="network" if "network_send" in detected_sinks else "email",
                confidence=0.85,
                attrs={"sinks": sorted(detected_sinks)},
            )
        )

    # --- High privilege call ---
    if "shell_exec" in detected_sinks:
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="is_high_privilege_call",
                object="shell_exec",
                confidence=0.9,
                attrs={"reason": "subprocess_or_exec_detected"},
            )
        )

    # --- Credential access ---
    if _any_match(_CREDENTIAL_PATTERNS, code):
        matches = _matching_pattern_texts(_CREDENTIAL_PATTERNS, code)
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="has_data_label",
                object="credential",
                confidence=0.75,
                attrs={"matches": matches[:5]},
            )
        )

    # --- PII / confidential data ---
    if _any_match(_PII_PATTERNS, code):
        matches = _matching_pattern_texts(_PII_PATTERNS, code)
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="has_data_label",
                object="confidential",
                confidence=0.65,
                attrs={"matches": matches[:5]},
            )
        )

    # --- Inferred capabilities (aggregate) ---
    capability_map = {
        "file_read": "file_read" in detected_sources,
        "file_write": "file_write" in detected_sinks,
        "network_write": "network_send" in detected_sinks,
        "shell_exec": "shell_exec" in detected_sinks,
        "email_send": "email_send" in detected_sinks,
        "memory_write": "memory_write" in detected_sinks,
        "credential_access": _any_match(_CREDENTIAL_PATTERNS, code),
    }
    for cap, present in capability_map.items():
        if present:
            evidence.append(
                Evidence(
                    kind="static",
                    subject=skill_name,
                    predicate="inferred_capability",
                    object=cap,
                    confidence=0.85,
                    attrs={"source": "static_pattern_match"},
                )
            )

    return evidence
