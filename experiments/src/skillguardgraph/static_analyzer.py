"""Lightweight static analyzer for skill source code.

Scans source code strings for common patterns that indicate security-relevant
capabilities and extracts conservative Python AST source--sink summaries without
executing code.
"""
from __future__ import annotations

import re
import ast
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



def _dotted_name(node: ast.AST) -> str:
    """Return a dotted call/attribute name for a Python AST node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _normalize_call_name(name: str, aliases: Dict[str, str]) -> str:
    if not name:
        return name
    head, sep, tail = name.partition(".")
    mapped = aliases.get(head)
    if mapped is None:
        return name
    return f"{mapped}.{tail}" if sep else mapped


def _target_names(target: ast.AST) -> List[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: List[str] = []
        for item in target.elts:
            names.extend(_target_names(item))
        return names
    return []


def _names_used(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _literal_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()
    return ""


def _call_source_kind(call_name: str) -> str | None:
    if call_name in {"os.getenv", "os.environ", "dotenv.get_key"}:
        return "env_var"
    if call_name in {"input", "getpass.getpass"} or call_name.startswith("request."):
        return "user_input"
    if call_name in {"open", "Path.read_text", "pathlib.Path.read_text", "read_file"}:
        return "file_read"
    if call_name.endswith(".execute") or call_name.endswith(".find") or call_name.endswith(".query"):
        return "database_query"
    return None


def _call_sink_kind(call_name: str) -> str | None:
    if call_name in {
        "requests.post", "requests.put", "requests.patch", "requests.delete",
        "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
        "urllib.request.urlopen", "fetch", "socket.send", "socket.connect",
    }:
        return "network_send"
    if call_name in {"send_email", "send_message", "sendmail"} or call_name.endswith(".sendmail"):
        return "email_send"
    if call_name in {"write_file", "Path.write_text", "pathlib.Path.write_text"}:
        return "file_write"
    if call_name in {"memory_write", "update_config", "set_config", "save_state"}:
        return "memory_write"
    if call_name in {"subprocess.run", "subprocess.Popen", "os.system", "os.popen", "exec", "eval"}:
        return "shell_exec"
    return None


def _source_label_for(source_kind: str) -> str:
    if source_kind in {"env_var", "user_input"}:
        return "untrusted"
    return "internal"


def _data_label_for(source_kind: str, value: ast.AST) -> str:
    text = " ".join(
        part
        for node in ast.walk(value)
        for part in (_dotted_name(node), _literal_text(node))
        if part
    ).lower()
    if source_kind == "env_var" or any(term in text for term in ("token", "secret", "api_key", "password", "credential")):
        return "credential"
    if any(term in text for term in ("ssn", "confidential", "personal", "customer")):
        return "confidential"
    return "unknown"


def _infer_import_aliases(tree: ast.AST) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _analyze_python_ast(skill_name: str, source_code: str) -> List[Evidence]:
    """Extract lightweight AST source-to-sink summaries for Python code."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []

    aliases = _infer_import_aliases(tree)
    tainted: Dict[str, tuple[str, str]] = {}
    evidence: List[Evidence] = []
    seen_paths: set[tuple[str, str, str, str]] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            source_kind = None
            data_label = "unknown"
            for child in ast.walk(node.value):
                if isinstance(child, ast.Call):
                    call_name = _normalize_call_name(_dotted_name(child.func), aliases)
                    source_kind = _call_source_kind(call_name)
                    if source_kind is not None:
                        data_label = _data_label_for(source_kind, node.value)
                        break
                elif isinstance(child, ast.Subscript):
                    subscript_name = _normalize_call_name(_dotted_name(child), aliases)
                    if subscript_name == "os.environ":
                        source_kind = "env_var"
                        data_label = _data_label_for(source_kind, node.value)
                        break
            if source_kind is None:
                used = _names_used(node.value)
                inherited = [tainted[name] for name in used if name in tainted]
                if inherited:
                    source_kind, data_label = inherited[0]
            if source_kind is not None:
                for target in node.targets:
                    for name in _target_names(target):
                        tainted[name] = (source_kind, data_label)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _normalize_call_name(_dotted_name(node.func), aliases)
        sink_kind = _call_sink_kind(call_name)
        if sink_kind is None:
            continue
        used_tainted = sorted(_names_used(node) & set(tainted))
        if not used_tainted:
            continue
        source_kind, data_label = tainted[used_tainted[0]]
        source_node = f"{skill_name}:static_source:{used_tainted[0]}"
        sink_node = f"{skill_name}:static_sink:{sink_kind}"
        path_key = (source_node, sink_node, source_kind, sink_kind)
        if path_key in seen_paths:
            continue
        seen_paths.add(path_key)

        label = data_label
        should_emit_policy_flow = label in {"credential", "confidential", "secret", "pii"} or sink_kind == "shell_exec"
        if should_emit_policy_flow:
            evidence.extend([
                Evidence(
                    kind="static",
                    subject=source_node,
                    predicate="has_source_label",
                    object=_source_label_for(source_kind),
                    confidence=0.78,
                    attrs={"source": "python_ast", "variable": used_tainted[0], "source_kind": source_kind},
                ),
                Evidence(
                    kind="static",
                    subject=source_node,
                    predicate="flows_to",
                    object=sink_node,
                    confidence=0.74,
                    attrs={"source": "python_ast", "call": call_name},
                ),
            ])
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="source_sink_path",
                object=f"{source_kind}->{sink_kind}",
                confidence=0.74,
                attrs={
                    "source": "python_ast",
                    "variable": used_tainted[0],
                    "data_label": label,
                    "call": call_name,
                },
            )
        )
        if label in {"credential", "confidential", "secret", "pii"}:
            evidence.append(
                Evidence(
                    kind="static",
                    subject=source_node,
                    predicate="has_data_label",
                    object=label,
                    confidence=0.78,
                    attrs={"source": "python_ast", "variable": used_tainted[0]},
                )
            )
        if should_emit_policy_flow:
            evidence.append(
                Evidence(
                    kind="static",
                    subject=sink_node,
                    predicate="sink_identified",
                    object=sink_kind,
                    confidence=0.8,
                    attrs={"source": "python_ast", "call": call_name},
                )
            )
        if sink_kind in {"network_send", "email_send"} and label in {"credential", "confidential", "secret", "pii"}:
            evidence.append(
                Evidence(
                    kind="static",
                    subject=sink_node,
                    predicate="is_external_sink",
                    object="network" if sink_kind == "network_send" else "email",
                    confidence=0.8,
                    attrs={"source": "python_ast", "call": call_name},
                )
            )
        if sink_kind == "shell_exec":
            evidence.append(
                Evidence(
                    kind="static",
                    subject=sink_node,
                    predicate="is_high_privilege_call",
                    object="shell_exec",
                    confidence=0.82,
                    attrs={"source": "python_ast", "call": call_name},
                )
            )

    return evidence
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

    This is a lightweight scanner. It does not execute code or invoke external
    SAST tools; its AST pass is an intraprocedural source--sink summary, not full taint tracking.
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


    # --- Python AST source-to-sink summaries ---
    evidence.extend(_analyze_python_ast(skill_name, code))
    return evidence
