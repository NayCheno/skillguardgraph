"""Lightweight static analyzer for skill source code.

Scans source code strings for common patterns that indicate security-relevant
capabilities and extracts conservative source--sink summaries without executing
code.
"""
from __future__ import annotations

import ast
import base64
import binascii
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .models import Evidence


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Network sinks: outbound data transfer
_NETWORK_SINK_PATTERNS = [
    re.compile(r"\brequests\.(?:request|post|put|patch|delete)\b"),
    re.compile(r"\bfetch\s*\("),
    re.compile(r"\b(?:globalThis|window)\.fetch\s*\("),
    re.compile(r"\baxios\s*\("),
    re.compile(r"\baxios\.(?:request|post|put|patch|delete|get)\b"),
    re.compile(r"\bhttps?\.request\b"),
    re.compile(r"\bhttp\.client\b"),
    re.compile(r"\burllib\.request\b"),
    re.compile(r"\bhttpx\.(?:request|post|put|patch|delete)\b"),
    re.compile(r"\baiohttp\.ClientSession\b"),
    re.compile(r"\bsocket\.(?:connect|send)\b"),
    re.compile(r"\bxmlrpc\.client\b"),
]

# File write / delete sinks
_FILE_WRITE_PATTERNS = [
    re.compile(r"""open\s*\([^)]*['\"][wax+]"""),
    re.compile(r"\bfs\.(?:promises\.)?(?:writeFile|appendFile|unlink|rm)\s*\("),
    re.compile(r"\bfs\.(?:writeFileSync|appendFileSync|unlinkSync|rmSync)\s*\("),
    re.compile(r"\bos\.remove\b"),
    re.compile(r"\bos\.unlink\b"),
    re.compile(r"\bshutil\.rmtree\b"),
    re.compile(r"\bshutil\.move\b"),
    re.compile(r"\bos\.rename\b"),
    re.compile(r"\bpathlib\.Path\([^)]*\)\.(?:write_|unlink)"),
    re.compile(r"\bPath\([^)]*\)\.(?:write_|unlink)"),
]

# Shell / exec sinks
_SHELL_PATTERNS = [
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bchild_process\.(?:exec|execSync|spawn|spawnSync)\b"),
    re.compile(r"\brequire\(['\"]child_process['\"]\)\.(?:exec|execSync|spawn|spawnSync)\b"),
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
    re.compile(r"\bprocess\.env(?:\.|\[)"),
    re.compile(r"\bdotenv\b"),
    re.compile(r"\bconfigparser\b"),
]

# File read source
_FILE_READ_PATTERNS = [
    re.compile(r"""open\s*\([^)]*['\"][r]"""),
    re.compile(r"\bfs\.(?:promises\.)?(?:readFile|readdir)\s*\("),
    re.compile(r"\bfs\.(?:readFileSync|readdirSync)\s*\("),
    re.compile(r"\bPath\([^)]*\)\.(?:read_|iterdir)"),
    re.compile(r"\bpathlib\.Path\([^)]*\)\.(?:read_|iterdir)"),
    re.compile(r"\bios\.listdir\b"),
    re.compile(r"\bglob\.glob\b"),
]

# User input source
_USER_INPUT_PATTERNS = [
    re.compile(r"\binput\s*\("),
    re.compile(r"\bjson\.loads\s*\(\s*request"),
    re.compile(r"\brequest\.(?:body|form|args|json)\b"),
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
    re.compile(r"\brequire\(['\"]crypto['\"]\)"),
    re.compile(r"\bcrypto\.createCipher(?:iv)?\b"),
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

_DATA_LABEL_PRIORITY = {
    "unknown": 0,
    "confidential": 1,
    "pii": 2,
    "secret": 3,
    "credential": 4,
}

_SOURCE_PRIORITY = {
    "database_query": 1,
    "file_read": 2,
    "user_input": 3,
    "env_var": 4,
}

_TRACKED_OBJECT_TYPES = {
    "Path",
    "pathlib.Path",
    "requests.Request",
    "requests.Session",
    "requests.sessions.Session",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
}

_URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s'\"`]+")
_COMMAND_RE = re.compile(r"(?i)\b(?:bash|sh|zsh|cmd(?:\.exe)?|powershell|pwsh|curl|wget|nc|ssh|scp|chmod|rm|del|mv)\b")
_BASE64_STRING_RE = re.compile(r"['\"`]([A-Za-z0-9+/]{16,}={0,2})['\"`]")
_PY_REVERSE_PATTERN = re.compile(r"\[\s*::\s*-1\s*\]")
_JS_REVERSE_PATTERN = re.compile(r"\.split\(\s*['\"`]\s*['\"`]\s*\)\.reverse\(\)\.join\(\s*['\"`]\s*['\"`]\s*\)")
_PY_CHR_PATTERN = re.compile(r"(?:\bchr\s*\(\s*\d{2,3}\s*\)\s*\+\s*){2,}\bchr\s*\(\s*\d{2,3}\s*\)")
_JS_CHARCODE_PATTERN = re.compile(r"(?:\bString\.fromCharCode\s*\(\s*\d{2,3}\s*\)\s*\+\s*){2,}\bString\.fromCharCode\s*\(\s*\d{2,3}\s*\)")


# ---------------------------------------------------------------------------
# Helper data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _ResolvedText:
    text: str | None
    obfuscation: tuple[str, ...] = ()


@dataclass(frozen=True)
class _TaintInfo:
    source_kind: str
    data_label: str
    obfuscation: tuple[str, ...] = ()


@dataclass
class _ScopeState:
    tainted: Dict[str, _TaintInfo] = field(default_factory=dict)
    call_aliases: Dict[str, str] = field(default_factory=dict)
    object_types: Dict[str, str] = field(default_factory=dict)
    string_values: Dict[str, _ResolvedText] = field(default_factory=dict)

    def child(self) -> "_ScopeState":
        return _ScopeState(
            tainted=self.tainted.copy(),
            call_aliases=self.call_aliases.copy(),
            object_types=self.object_types.copy(),
            string_values=self.string_values.copy(),
        )


@dataclass
class _AnalysisResult:
    evidence: List[Evidence] = field(default_factory=list)
    sink_matches: Dict[str, List[str]] = field(default_factory=dict)
    source_matches: Dict[str, List[str]] = field(default_factory=dict)
    data_label_matches: Dict[str, List[str]] = field(default_factory=dict)
    obfuscation_matches: List[str] = field(default_factory=list)

    def add_sink(self, sink_kind: str, match: str) -> None:
        if match:
            self.sink_matches.setdefault(sink_kind, []).append(match)

    def add_source(self, source_kind: str, match: str) -> None:
        if match:
            self.source_matches.setdefault(source_kind, []).append(match)

    def add_data_label(self, label: str, match: str) -> None:
        if match:
            self.data_label_matches.setdefault(label, []).append(match)

    def add_obfuscation(self, match: str) -> None:
        if match:
            self.obfuscation_matches.append(match)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _any_match(patterns: List[re.Pattern[str]], text: str) -> bool:
    return any(p.search(text) for p in patterns)



def _merge_matches(*groups: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for group in groups:
        for item in group:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
    return out



def _freeze_attrs(value: object) -> object:
    if isinstance(value, dict):
        return tuple(sorted((k, _freeze_attrs(v)) for k, v in value.items()))
    if isinstance(value, list):
        return tuple(_freeze_attrs(v) for v in value)
    if isinstance(value, set):
        return tuple(sorted(_freeze_attrs(v) for v in value))
    if isinstance(value, tuple):
        return tuple(_freeze_attrs(v) for v in value)
    return value



def _dedupe_evidence(evidence: List[Evidence]) -> List[Evidence]:
    seen: set[tuple[object, ...]] = set()
    out: List[Evidence] = []
    for ev in evidence:
        key = (ev.kind, ev.subject, ev.predicate, ev.object, _freeze_attrs(ev.attrs))
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)
    return out



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
    if mapped is None or mapped == head:
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



def _prefer_data_label(*labels: str) -> str:
    best = "unknown"
    for label in labels:
        if _DATA_LABEL_PRIORITY.get(label, 0) > _DATA_LABEL_PRIORITY.get(best, 0):
            best = label
    return best



def _prefer_source_kind(*source_kinds: str) -> str:
    best = "file_read"
    for source_kind in source_kinds:
        if _SOURCE_PRIORITY.get(source_kind, 0) > _SOURCE_PRIORITY.get(best, 0):
            best = source_kind
    return best



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
    if source_kind == "env_var" or any(term in text for term in ("token", "secret", "api_key", "password", "credential", "cipher", "auth")):
        return "credential"
    if any(term in text for term in ("ssn", "confidential", "personal", "customer")):
        return "confidential"
    return "unknown"



def _infer_import_aliases(tree: ast.AST) -> Dict[str, str]:
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    aliases[root] = root
                    aliases[alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_name = alias.asname or alias.name
                aliases[local_name] = f"{node.module}.{alias.name}"
    return aliases



def _looks_like_url(text: str) -> bool:
    return bool(_URL_RE.search(text))



def _looks_like_command(text: str) -> bool:
    return bool(_COMMAND_RE.search(text))



def _safe_b64decode_text(value: str) -> str | None:
    cleaned = re.sub(r"\s+", "", value)
    if len(cleaned) < 12 or not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", cleaned):
        return None
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        decoded = base64.b64decode(cleaned, validate=False)
    except (ValueError, binascii.Error):
        return None
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = decoded.decode("latin-1")
        except UnicodeDecodeError:
            return None
    if not text:
        return None
    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    if printable / len(text) < 0.85:
        return None
    return text



def _detect_text_obfuscation(text: str) -> List[str]:
    matches: List[str] = []
    for match in _BASE64_STRING_RE.finditer(text):
        decoded = _safe_b64decode_text(match.group(1))
        if decoded and (_looks_like_url(decoded) or _looks_like_command(decoded)):
            label = "url" if _looks_like_url(decoded) else "command"
            matches.append(f"base64_{label}:{decoded[:80]}")
    if _PY_REVERSE_PATTERN.search(text):
        matches.append("string_reverse:slice")
    if _JS_REVERSE_PATTERN.search(text):
        matches.append("string_reverse:split_reverse_join")
    chr_match = _PY_CHR_PATTERN.search(text)
    if chr_match:
        matches.append(f"charcode_assembly:{chr_match.group()[:80]}")
    js_char_match = _JS_CHARCODE_PATTERN.search(text)
    if js_char_match:
        matches.append(f"charcode_assembly:{js_char_match.group()[:80]}")
    return _merge_matches(matches)



def _open_mode(call: ast.Call) -> str:
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str):
        return call.args[1].value
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
            return keyword.value.value
    return ""



def _call_source_kind(call_name: str, call: ast.Call | None = None) -> str | None:
    if call_name in {"os.getenv", "os.environ.get", "dotenv.get_key"}:
        return "env_var"
    if call_name in {"input", "getpass.getpass"} or call_name.startswith("request."):
        return "user_input"
    if call_name in {"Path.read_text", "Path.read_bytes", "pathlib.Path.read_text", "pathlib.Path.read_bytes", "read_file"}:
        return "file_read"
    if call_name == "open" and call is not None:
        mode = _open_mode(call)
        if not mode or mode.startswith("r"):
            return "file_read"
    if call_name.endswith(".execute") or call_name.endswith(".find") or call_name.endswith(".query"):
        return "database_query"
    return None



def _call_sink_kind(call_name: str, call: ast.Call | None = None) -> str | None:
    if call_name in {
        "requests.request",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.Session.send",
        "requests.sessions.Session.send",
        "requests.Session.request",
        "requests.sessions.Session.request",
        "httpx.request",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "urllib.request.urlopen",
        "http.client.HTTPConnection.request",
        "http.client.HTTPSConnection.request",
        "fetch",
        "socket.send",
        "socket.connect",
    }:
        return "network_send"
    if call_name in {"send_email", "send_message", "sendmail"} or call_name.endswith(".sendmail"):
        return "email_send"
    if call_name in {
        "write_file",
        "Path.write_text",
        "Path.write_bytes",
        "Path.unlink",
        "pathlib.Path.write_text",
        "pathlib.Path.write_bytes",
        "pathlib.Path.unlink",
    }:
        return "file_write"
    if call_name == "open" and call is not None:
        mode = _open_mode(call)
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            return "file_write"
    if call_name in {"memory_write", "update_config", "set_config", "save_state"}:
        return "memory_write"
    if call_name in {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "exec",
        "eval",
    }:
        return "shell_exec"
    return None



def _matching_pattern_texts(patterns: List[re.Pattern[str]], text: str) -> List[str]:
    """Return the first matched substring for each pattern that fires."""
    seen: set[str] = set()
    out: List[str] = []
    for pattern in patterns:
        match = pattern.search(text)
        if match and match.group() not in seen:
            seen.add(match.group())
            out.append(match.group())
    return out



def _parse_js_named_members(raw_members: str) -> List[tuple[str, str]]:
    members: List[tuple[str, str]] = []
    for part in raw_members.split(","):
        item = part.strip()
        if not item:
            continue
        match = re.match(r"^([A-Za-z_$][\w$]*)\s+(?:as)\s+([A-Za-z_$][\w$]*)$", item)
        if not match:
            match = re.match(r"^([A-Za-z_$][\w$]*)\s*:\s*([A-Za-z_$][\w$]*)$", item)
        if match:
            members.append((match.group(1), match.group(2)))
        else:
            members.append((item, item))
    return members



def _js_member_canonical(module_name: str, member_name: str) -> str | None:
    if module_name == "axios" and member_name in {"request", "post", "put", "patch", "delete", "get"}:
        return f"axios.{member_name}"
    if module_name == "fs" and member_name == "promises":
        return "fs.promises"
    if module_name == "fs" and member_name in {
        "writeFile",
        "writeFileSync",
        "appendFile",
        "appendFileSync",
        "unlink",
        "unlinkSync",
        "rm",
        "rmSync",
        "readFile",
        "readFileSync",
        "readdir",
        "readdirSync",
    }:
        return f"fs.{member_name}"
    if module_name in {"http", "https"} and member_name in {"request", "get"}:
        return f"{module_name}.{member_name}"
    if module_name == "child_process" and member_name in {"exec", "execSync", "spawn", "spawnSync"}:
        return f"child_process.{member_name}"
    if module_name == "crypto" and member_name in {"createCipher", "createCipheriv"}:
        return f"crypto.{member_name}"
    return None



def _js_canonical_category(canonical_name: str) -> tuple[str, str] | None:
    if canonical_name in {"fetch"} or canonical_name.startswith("axios") or canonical_name in {"http.request", "https.request", "http.get", "https.get"}:
        return ("sink", "network_send")
    if canonical_name.startswith("fs.") and any(part in canonical_name for part in ("writeFile", "appendFile", "unlink", "rm")):
        return ("sink", "file_write")
    if canonical_name.startswith("fs.") and any(part in canonical_name for part in ("readFile", "readdir")):
        return ("source", "file_read")
    if canonical_name.startswith("child_process."):
        return ("sink", "shell_exec")
    if canonical_name in {"crypto", "crypto.createCipher", "crypto.createCipheriv"} or canonical_name.startswith("crypto."):
        return ("data_label", "credential")
    return None



def _analyze_jsts_patterns(source_code: str) -> _AnalysisResult:
    result = _AnalysisResult()
    module_aliases: Dict[str, set[str]] = {
        "axios": set(),
        "fs": set(),
        "fs.promises": set(),
        "http": set(),
        "https": set(),
        "child_process": set(),
        "crypto": set(),
    }
    call_aliases: Dict[str, str] = {}

    def register_module_alias(module_name: str, alias_name: str) -> None:
        if module_name in module_aliases and alias_name:
            module_aliases[module_name].add(alias_name)
            if module_name == "crypto":
                result.add_data_label("credential", f"{alias_name} -> crypto")

    default_import_re = re.compile(r"\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+['\"](axios|fs|http|https|child_process|crypto)['\"]")
    namespace_import_re = re.compile(r"\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['\"](axios|fs|http|https|child_process|crypto)['\"]")
    require_alias_re = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['\"](axios|fs|http|https|child_process|crypto)['\"]\)")
    named_import_re = re.compile(r"\bimport\s*\{([^}]+)\}\s*from\s*['\"](axios|fs|http|https|child_process|crypto)['\"]")
    destructured_require_re = re.compile(r"\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['\"](axios|fs|http|https|child_process|crypto)['\"]\)")

    for match in default_import_re.finditer(source_code):
        register_module_alias(match.group(2), match.group(1))
    for match in namespace_import_re.finditer(source_code):
        register_module_alias(match.group(2), match.group(1))
    for match in require_alias_re.finditer(source_code):
        register_module_alias(match.group(2), match.group(1))
        if match.group(2) == "crypto":
            result.add_data_label("credential", match.group())
    for match in named_import_re.finditer(source_code):
        module_name = match.group(2)
        for original, local_name in _parse_js_named_members(match.group(1)):
            canonical = _js_member_canonical(module_name, original)
            if canonical is None:
                continue
            if canonical == "fs.promises":
                register_module_alias("fs.promises", local_name)
            else:
                call_aliases[local_name] = canonical
            category = _js_canonical_category(canonical)
            if category == ("data_label", "credential"):
                result.add_data_label("credential", f"{local_name} -> {canonical}")
    for match in destructured_require_re.finditer(source_code):
        module_name = match.group(2)
        for original, local_name in _parse_js_named_members(match.group(1)):
            canonical = _js_member_canonical(module_name, original)
            if canonical is None:
                continue
            if canonical == "fs.promises":
                register_module_alias("fs.promises", local_name)
            else:
                call_aliases[local_name] = canonical
            if module_name == "crypto":
                result.add_data_label("credential", match.group())

    expression_aliases: Dict[str, str] = {"fetch": "fetch"}
    expression_aliases.update(call_aliases)
    for module_name, aliases in module_aliases.items():
        for alias_name in aliases:
            expression_aliases[alias_name] = module_name

    assignment_re = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")
    property_re = re.compile(r"^([A-Za-z_$][\w$]*)\.(\w+)$")
    require_property_re = re.compile(r"^require\(['\"](axios|fs|http|https|child_process|crypto)['\"]\)\.(\w+)$")

    def resolve_js_expression(expr: str) -> str | None:
        candidate = expr.strip()
        if candidate in expression_aliases:
            return expression_aliases[candidate]
        property_match = property_re.match(candidate)
        if property_match:
            base_name, member_name = property_match.groups()
            base_canonical = expression_aliases.get(base_name)
            if base_canonical == "axios" and member_name in {"request", "post", "put", "patch", "delete", "get"}:
                return f"axios.{member_name}"
            if base_canonical in {"fs", "fs.promises"} and member_name in {
                "writeFile",
                "writeFileSync",
                "appendFile",
                "appendFileSync",
                "unlink",
                "unlinkSync",
                "rm",
                "rmSync",
                "readFile",
                "readFileSync",
                "readdir",
                "readdirSync",
            }:
                return f"fs.{member_name}"
            if base_canonical in {"http", "https"} and member_name in {"request", "get"}:
                return f"{base_canonical}.{member_name}"
            if base_canonical == "child_process" and member_name in {"exec", "execSync", "spawn", "spawnSync"}:
                return f"child_process.{member_name}"
            if base_canonical == "crypto" and member_name in {"createCipher", "createCipheriv"}:
                return f"crypto.{member_name}"
        require_property_match = require_property_re.match(candidate)
        if require_property_match:
            module_name, member_name = require_property_match.groups()
            return _js_member_canonical(module_name, member_name)
        return None

    for _ in range(3):
        changed = False
        for match in assignment_re.finditer(source_code):
            local_name, rhs = match.groups()
            canonical = resolve_js_expression(rhs)
            if canonical and expression_aliases.get(local_name) != canonical:
                expression_aliases[local_name] = canonical
                category = _js_canonical_category(canonical)
                if category == ("data_label", "credential"):
                    result.add_data_label("credential", f"{local_name} -> {canonical}")
                changed = True
        if not changed:
            break

    for alias_name in module_aliases["axios"]:
        if re.search(rf"\b{re.escape(alias_name)}\s*\(", source_code):
            result.add_sink("network_send", f"{alias_name}(...) -> axios")
        if re.search(rf"\b{re.escape(alias_name)}\.(?:request|post|put|patch|delete|get)\s*\(", source_code):
            result.add_sink("network_send", f"{alias_name}.request")
    for module_name in ("http", "https"):
        for alias_name in module_aliases[module_name]:
            if re.search(rf"\b{re.escape(alias_name)}\.request\s*\(", source_code):
                result.add_sink("network_send", f"{alias_name}.request")
    for alias_name in module_aliases["fs"] | module_aliases["fs.promises"]:
        if re.search(rf"\b{re.escape(alias_name)}\.(?:writeFile|writeFileSync|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync)\s*\(", source_code):
            result.add_sink("file_write", f"{alias_name}.writeFile")
        if re.search(rf"\b{re.escape(alias_name)}\.(?:readFile|readFileSync|readdir|readdirSync)\s*\(", source_code):
            result.add_source("file_read", f"{alias_name}.readFile")
    for alias_name in module_aliases["child_process"]:
        if re.search(rf"\b{re.escape(alias_name)}\.(?:exec|execSync|spawn|spawnSync)\s*\(", source_code):
            result.add_sink("shell_exec", f"{alias_name}.exec")
    for alias_name in module_aliases["crypto"]:
        if re.search(rf"\b{re.escape(alias_name)}\.createCipher(?:iv)?\s*\(", source_code):
            result.add_data_label("credential", f"{alias_name}.createCipher")

    for local_name, canonical_name in expression_aliases.items():
        category = _js_canonical_category(canonical_name)
        if category is None:
            continue
        kind, label = category
        if canonical_name in {"fs", "fs.promises", "http", "https", "child_process", "axios", "crypto"}:
            continue
        if re.search(rf"\b{re.escape(local_name)}\s*\(", source_code):
            if kind == "sink":
                result.add_sink(label, f"{local_name}(...) -> {canonical_name}")
            elif kind == "source":
                result.add_source(label, f"{local_name}(...) -> {canonical_name}")
            elif kind == "data_label":
                result.add_data_label(label, f"{local_name}(...) -> {canonical_name}")

    return result


class _PythonFlowAnalyzer:
    def __init__(self, skill_name: str, tree: ast.AST) -> None:
        self.skill_name = skill_name
        self.tree = tree
        self.aliases = _infer_import_aliases(tree)
        self.result = _AnalysisResult()
        self.seen_paths: set[tuple[str, str, str, str, str]] = set()

    def analyze(self) -> _AnalysisResult:
        root_scope = _ScopeState(call_aliases=self.aliases.copy())
        self._visit_block(getattr(self.tree, "body", []), root_scope)
        return self.result

    def _visit_block(self, statements: List[ast.stmt], scope: _ScopeState) -> None:
        for statement in statements:
            self._visit_statement(statement, scope)

    def _visit_statement(self, statement: ast.stmt, scope: _ScopeState) -> None:
        if isinstance(statement, ast.Assign):
            self._handle_assignment(statement.targets, statement.value, scope)
            self._inspect_calls(statement.value, scope)
            return
        if isinstance(statement, ast.AnnAssign):
            self._handle_assignment([statement.target], statement.value, scope)
            if statement.value is not None:
                self._inspect_calls(statement.value, scope)
            return
        if isinstance(statement, ast.AugAssign):
            self._handle_augmented_assignment(statement, scope)
            self._inspect_calls(statement.value, scope)
            return
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._clear_name_bindings(scope, statement.name)
            child_scope = scope.child()
            for decorator in statement.decorator_list:
                self._inspect_calls(decorator, scope)
            for default in list(statement.args.defaults) + list(statement.args.kw_defaults):
                if default is not None:
                    self._inspect_calls(default, scope)
            self._visit_block(statement.body, child_scope)
            return
        if isinstance(statement, ast.ClassDef):
            self._clear_name_bindings(scope, statement.name)
            child_scope = scope.child()
            for decorator in statement.decorator_list:
                self._inspect_calls(decorator, scope)
            self._visit_block(statement.body, child_scope)
            return
        if isinstance(statement, ast.If):
            self._inspect_calls(statement.test, scope)
            body_scope = scope.child()
            else_scope = scope.child()
            self._visit_block(statement.body, body_scope)
            self._visit_block(statement.orelse, else_scope)
            self._merge_branch_scopes(scope, body_scope, else_scope)
            return
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            self._inspect_calls(statement.iter, scope)
            for name in _target_names(statement.target):
                self._clear_name_bindings(scope, name)
            body_scope = scope.child()
            else_scope = scope.child()
            self._visit_block(statement.body, body_scope)
            self._visit_block(statement.orelse, else_scope)
            self._merge_branch_scopes(scope, body_scope, else_scope)
            return
        if isinstance(statement, ast.While):
            self._inspect_calls(statement.test, scope)
            body_scope = scope.child()
            else_scope = scope.child()
            self._visit_block(statement.body, body_scope)
            self._visit_block(statement.orelse, else_scope)
            self._merge_branch_scopes(scope, body_scope, else_scope)
            return
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                self._inspect_calls(item.context_expr, scope)
                if item.optional_vars is not None:
                    for name in _target_names(item.optional_vars):
                        self._clear_name_bindings(scope, name)
            self._visit_block(statement.body, scope)
            return
        if isinstance(statement, ast.Try):
            body_scope = scope.child()
            self._visit_block(statement.body, body_scope)
            handler_scopes = [scope.child() for _ in statement.handlers]
            for handler, handler_scope in zip(statement.handlers, handler_scopes):
                if handler.type is not None:
                    self._inspect_calls(handler.type, scope)
                if handler.name:
                    self._clear_name_bindings(handler_scope, handler.name)
                self._visit_block(handler.body, handler_scope)
            else_scope = scope.child()
            self._visit_block(statement.orelse, else_scope)
            final_scope = scope.child()
            self._visit_block(statement.finalbody, final_scope)
            self._merge_branch_scopes(scope, body_scope, else_scope, final_scope, *handler_scopes)
            return
        if isinstance(statement, ast.Return) and statement.value is not None:
            self._inspect_calls(statement.value, scope)
            return
        if isinstance(statement, ast.Expr):
            self._inspect_calls(statement.value, scope)
            return
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.AST):
                self._inspect_calls(child, scope)

    def _handle_assignment(self, targets: List[ast.AST], value: ast.AST | None, scope: _ScopeState) -> None:
        if value is None:
            return
        source_taint = self._direct_source_taint(value, scope)
        propagated_taint = self._propagated_taint(value, scope)
        taint = source_taint or propagated_taint
        text_value = self._extract_string(value, scope)
        object_type = self._infer_object_type(value, scope)
        callable_alias = self._callable_alias_for_value(value, scope)
        if text_value.text and text_value.obfuscation and (_looks_like_url(text_value.text) or _looks_like_command(text_value.text)):
            label = "url" if _looks_like_url(text_value.text) else "command"
            self.result.add_obfuscation(f"{label}:{'|'.join(text_value.obfuscation)}:{text_value.text[:80]}")
        for target in targets:
            for name in _target_names(target):
                if taint is not None:
                    scope.tainted[name] = taint
                else:
                    scope.tainted.pop(name, None)
                if text_value.text is not None:
                    scope.string_values[name] = text_value
                else:
                    scope.string_values.pop(name, None)
                if object_type is not None:
                    scope.object_types[name] = object_type
                else:
                    scope.object_types.pop(name, None)
                if callable_alias is not None:
                    scope.call_aliases[name] = callable_alias
                else:
                    scope.call_aliases.pop(name, None)

    def _handle_augmented_assignment(self, statement: ast.AugAssign, scope: _ScopeState) -> None:
        target_names = _target_names(statement.target)
        source_taint = self._propagated_taint(statement.value, scope)
        existing_taints = [scope.tainted[name] for name in target_names if name in scope.tainted]
        taint = self._combine_taints(existing_taints + ([source_taint] if source_taint is not None else []))
        text_value = self._extract_string(statement.value, scope)
        for name in target_names:
            if taint is not None:
                scope.tainted[name] = taint
            if text_value.text is not None and name in scope.string_values and scope.string_values[name].text is not None:
                combined_text = _ResolvedText(
                    f"{scope.string_values[name].text}{text_value.text}",
                    tuple(sorted(set(scope.string_values[name].obfuscation) | set(text_value.obfuscation) | {"string_concat"})),
                )
                scope.string_values[name] = combined_text
            else:
                scope.string_values.pop(name, None)
            scope.call_aliases.pop(name, None)
            scope.object_types.pop(name, None)

    def _merge_branch_scopes(self, base_scope: _ScopeState, *branches: _ScopeState) -> None:
        for mapping_name in ("tainted", "call_aliases", "object_types", "string_values"):
            merged = getattr(base_scope, mapping_name).copy()
            branch_maps = [getattr(branch, mapping_name) for branch in branches]
            for key in {item for branch_map in branch_maps for item in branch_map}:
                values = [branch_map[key] for branch_map in branch_maps if key in branch_map]
                if not values:
                    continue
                if mapping_name == "tainted":
                    merged[key] = self._combine_taints(values) or values[0]
                elif all(value == values[0] for value in values[1:]):
                    merged[key] = values[0]
                elif mapping_name == "string_values":
                    texts = [value.text for value in values if value.text is not None]
                    if texts and all(text == texts[0] for text in texts[1:]):
                        obfuscation = tuple(sorted({flag for value in values for flag in value.obfuscation}))
                        merged[key] = _ResolvedText(texts[0], obfuscation)
            setattr(base_scope, mapping_name, merged)

    def _clear_name_bindings(self, scope: _ScopeState, name: str) -> None:
        scope.tainted.pop(name, None)
        scope.call_aliases.pop(name, None)
        scope.object_types.pop(name, None)
        scope.string_values.pop(name, None)

    def _resolve_name(self, node: ast.AST, scope: _ScopeState) -> str:
        if isinstance(node, ast.Name):
            return scope.call_aliases.get(node.id) or self.aliases.get(node.id) or node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_name(node.value, scope)
            if isinstance(node.value, ast.Name) and node.value.id in scope.object_types:
                resolved_base = scope.call_aliases.get(node.value.id) or self.aliases.get(node.value.id)
                if resolved_base is None:
                    base = scope.object_types[node.value.id]
                else:
                    base = resolved_base
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Subscript):
            return self._resolve_name(node.value, scope)
        if isinstance(node, ast.Call):
            if self._is_getattr_reference(node, scope):
                base = self._resolve_name(node.args[0], scope)
                attr_name = self._extract_string(node.args[1], scope)
                if base and attr_name.text:
                    if attr_name.obfuscation:
                        self.result.add_obfuscation(f"sink_alias:{'|'.join(attr_name.obfuscation)}:{base}.{attr_name.text}")
                    return f"{base}.{attr_name.text}"
            return self._resolve_name(node.func, scope)
        return ""

    def _resolve_call_name(self, node: ast.AST, scope: _ScopeState) -> str:
        return self._resolve_name(node, scope)

    def _is_getattr_reference(self, node: ast.Call, scope: _ScopeState) -> bool:
        return (
            self._resolve_name(node.func, scope) == "getattr"
            and len(node.args) >= 2
        )

    def _direct_source_taint(self, value: ast.AST, scope: _ScopeState) -> _TaintInfo | None:
        for child in ast.walk(value):
            if isinstance(child, ast.Call):
                call_name = self._resolve_call_name(child.func, scope)
                source_kind = _call_source_kind(call_name, child)
                if source_kind is not None:
                    self.result.add_source(source_kind, call_name)
                    return _TaintInfo(
                        source_kind=source_kind,
                        data_label=_data_label_for(source_kind, value),
                        obfuscation=self._obfuscation_flags_for_expression(value, scope),
                    )
            elif isinstance(child, (ast.Subscript, ast.Attribute)):
                resolved_name = self._resolve_name(child, scope)
                if resolved_name == "os.environ":
                    self.result.add_source("env_var", "os.environ")
                    return _TaintInfo(
                        source_kind="env_var",
                        data_label=_data_label_for("env_var", value),
                        obfuscation=self._obfuscation_flags_for_expression(value, scope),
                    )
        return None

    def _propagated_taint(self, value: ast.AST, scope: _ScopeState) -> _TaintInfo | None:
        taints = [scope.tainted[name] for name in sorted(_names_used(value)) if name in scope.tainted]
        if not taints:
            return None
        obfuscation = set(self._obfuscation_flags_for_expression(value, scope))
        for taint in taints:
            obfuscation.update(taint.obfuscation)
        return _TaintInfo(
            source_kind=_prefer_source_kind(*(taint.source_kind for taint in taints)),
            data_label=_prefer_data_label(*(taint.data_label for taint in taints)),
            obfuscation=tuple(sorted(obfuscation)),
        )

    def _combine_taints(self, taints: List[_TaintInfo | None]) -> _TaintInfo | None:
        present = [taint for taint in taints if taint is not None]
        if not present:
            return None
        return _TaintInfo(
            source_kind=_prefer_source_kind(*(taint.source_kind for taint in present)),
            data_label=_prefer_data_label(*(taint.data_label for taint in present)),
            obfuscation=tuple(sorted({flag for taint in present for flag in taint.obfuscation})),
        )

    def _callable_alias_for_value(self, value: ast.AST, scope: _ScopeState) -> str | None:
        if isinstance(value, (ast.Name, ast.Attribute)):
            return self._resolve_name(value, scope)
        if isinstance(value, ast.Call) and self._is_getattr_reference(value, scope):
            return self._resolve_name(value, scope)
        return None

    def _infer_object_type(self, value: ast.AST, scope: _ScopeState) -> str | None:
        if not isinstance(value, ast.Call):
            return None
        constructor_name = self._resolve_call_name(value.func, scope)
        if constructor_name in _TRACKED_OBJECT_TYPES:
            return constructor_name
        if constructor_name.endswith((".Session", ".Request", ".Path", ".HTTPConnection", ".HTTPSConnection")):
            return constructor_name
        return None

    def _slice_step_value(self, node: ast.AST | None) -> int | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant) and isinstance(node.operand.value, int):
            return -node.operand.value
        return None

    def _extract_string_collection(self, node: ast.AST, scope: _ScopeState) -> List[_ResolvedText] | None:
        if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return None
        items: List[_ResolvedText] = []
        for item in node.elts:
            resolved = self._extract_string(item, scope)
            if resolved.text is None:
                return None
            items.append(resolved)
        return items

    def _extract_string(self, node: ast.AST, scope: _ScopeState) -> _ResolvedText:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return _ResolvedText(node.value)
            if isinstance(node.value, bytes):
                try:
                    return _ResolvedText(node.value.decode("utf-8"))
                except UnicodeDecodeError:
                    return _ResolvedText(None)
        if isinstance(node, ast.Name):
            return scope.string_values.get(node.id, _ResolvedText(None))
        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            obfuscation: set[str] = set()
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    resolved = self._extract_string(value.value, scope)
                    if resolved.text is None:
                        return _ResolvedText(None)
                    parts.append(resolved.text)
                    obfuscation.update(resolved.obfuscation)
                else:
                    return _ResolvedText(None)
            return _ResolvedText("".join(parts), tuple(sorted(obfuscation)))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._extract_string(node.left, scope)
            right = self._extract_string(node.right, scope)
            if left.text is not None and right.text is not None:
                return _ResolvedText(
                    left.text + right.text,
                    tuple(sorted(set(left.obfuscation) | set(right.obfuscation) | {"string_concat"})),
                )
        if isinstance(node, ast.Call):
            func_name = self._resolve_call_name(node.func, scope)
            if func_name == "chr" and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
                value = node.args[0].value
                if 0 <= value <= 0x10FFFF:
                    return _ResolvedText(chr(value), ("charcode_assembly",))
            if func_name in {"base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode"} and node.args:
                encoded = self._extract_string(node.args[0], scope)
                if encoded.text is not None:
                    decoded = _safe_b64decode_text(encoded.text)
                    if decoded is not None:
                        return _ResolvedText(
                            decoded,
                            tuple(sorted(set(encoded.obfuscation) | {"base64_decode"})),
                        )
            if isinstance(node.func, ast.Attribute) and node.func.attr == "decode":
                inner = self._extract_string(node.func.value, scope)
                if inner.text is not None:
                    return inner
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and len(node.args) == 1:
                separator = self._extract_string(node.func.value, scope)
                items = self._extract_string_collection(node.args[0], scope)
                if separator.text is not None and items is not None:
                    return _ResolvedText(
                        separator.text.join(item.text or "" for item in items),
                        tuple(sorted(set(separator.obfuscation) | {flag for item in items for flag in item.obfuscation})),
                    )
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            step_value = self._slice_step_value(node.slice.step)
            if step_value == -1 and node.slice.lower is None and node.slice.upper is None:
                inner = self._extract_string(node.value, scope)
                if inner.text is not None:
                    return _ResolvedText(
                        inner.text[::-1],
                        tuple(sorted(set(inner.obfuscation) | {"string_reverse"})),
                    )
        return _ResolvedText(None)

    def _obfuscation_flags_for_expression(self, node: ast.AST, scope: _ScopeState) -> tuple[str, ...]:
        flags: set[str] = set()
        for child in ast.walk(node):
            resolved = self._extract_string(child, scope)
            if resolved.text is not None and resolved.obfuscation:
                flags.update(resolved.obfuscation)
        return tuple(sorted(flags))

    def _inspect_calls(self, node: ast.AST, scope: _ScopeState) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._inspect_call(child, scope)

    def _inspect_call(self, call: ast.Call, scope: _ScopeState) -> None:
        call_name = self._resolve_call_name(call.func, scope)
        sink_kind = _call_sink_kind(call_name, call)
        if sink_kind is not None:
            self.result.add_sink(sink_kind, call_name)
        for argument in list(call.args) + [keyword.value for keyword in call.keywords]:
            resolved = self._extract_string(argument, scope)
            if resolved.text is not None and resolved.obfuscation and (_looks_like_url(resolved.text) or _looks_like_command(resolved.text)):
                label = "url" if _looks_like_url(resolved.text) else "command"
                self.result.add_obfuscation(f"{label}:{'|'.join(resolved.obfuscation)}:{resolved.text[:80]}")
        if sink_kind is None:
            return
        used_tainted = sorted(_names_used(call) & set(scope.tainted))
        if not used_tainted:
            return
        for variable_name in used_tainted:
            taint = scope.tainted[variable_name]
            source_node = f"{self.skill_name}:static_source:{variable_name}"
            sink_node = f"{self.skill_name}:static_sink:{sink_kind}"
            path_key = (source_node, sink_node, taint.source_kind, sink_kind, variable_name)
            if path_key in self.seen_paths:
                continue
            self.seen_paths.add(path_key)
            should_emit_policy_flow = (
                taint.data_label in {"credential", "confidential", "secret", "pii"}
                or sink_kind == "shell_exec"
            )
            if should_emit_policy_flow:
                self.result.evidence.extend([
                    Evidence(
                        kind="static",
                        subject=source_node,
                        predicate="has_source_label",
                        object=_source_label_for(taint.source_kind),
                        confidence=0.78,
                        attrs={
                            "source": "python_ast",
                            "variable": variable_name,
                            "source_kind": taint.source_kind,
                        },
                    ),
                    Evidence(
                        kind="static",
                        subject=source_node,
                        predicate="flows_to",
                        object=sink_node,
                        confidence=0.74,
                        attrs={
                            "source": "python_ast",
                            "call": call_name,
                            "obfuscation": list(taint.obfuscation),
                        },
                    ),
                ])
            if should_emit_policy_flow:
                self.result.evidence.append(
                    Evidence(
                        kind="static",
                        subject=self.skill_name,
                        predicate="source_sink_path",
                        object=f"{taint.source_kind}->{sink_kind}",
                        confidence=0.74,
                        attrs={
                            "source": "python_ast",
                            "variable": variable_name,
                            "data_label": taint.data_label,
                            "call": call_name,
                            "obfuscation": list(taint.obfuscation),
                        },
                    )
                )
                self.result.add_data_label(taint.data_label, variable_name)
                self.result.evidence.append(
                    Evidence(
                        kind="static",
                        subject=source_node,
                        predicate="has_data_label",
                        object=taint.data_label,
                        confidence=0.78,
                        attrs={
                            "source": "python_ast",
                            "variable": variable_name,
                        },
                    )
                )
            if should_emit_policy_flow:
                self.result.evidence.append(
                    Evidence(
                        kind="static",
                        subject=sink_node,
                        predicate="sink_identified",
                        object=sink_kind,
                        confidence=0.8,
                        attrs={"source": "python_ast", "call": call_name},
                    )
                )
            if sink_kind in {"network_send", "email_send"} and taint.data_label in {"credential", "confidential", "secret", "pii"}:
                self.result.evidence.append(
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
                self.result.evidence.append(
                    Evidence(
                        kind="static",
                        subject=sink_node,
                        predicate="is_high_privilege_call",
                        object="shell_exec",
                        confidence=0.82,
                        attrs={"source": "python_ast", "call": call_name},
                    )
                )



def _analyze_python_ast(skill_name: str, source_code: str) -> _AnalysisResult:
    """Extract lightweight AST source-to-sink summaries for Python code."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return _AnalysisResult()
    return _PythonFlowAnalyzer(skill_name, tree).analyze()


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
    js_result = _analyze_jsts_patterns(code)
    python_result = _analyze_python_ast(skill_name, code)

    # --- Sinks ---
    detected_sinks: set[str] = set()
    for patterns, predicate, sink_kind in _SINK_GROUPS:
        matches = _merge_matches(
            _matching_pattern_texts(patterns, code),
            js_result.sink_matches.get(sink_kind, []),
            python_result.sink_matches.get(sink_kind, []),
        )
        if matches:
            detected_sinks.add(sink_kind)
            evidence.append(
                Evidence(
                    kind="static",
                    subject=skill_name,
                    predicate=predicate,
                    object=sink_kind,
                    confidence=0.85,
                    attrs={"matches": matches[:5]},
                )
            )

    # --- Sources ---
    detected_sources: set[str] = set()
    for patterns, predicate, source_kind in _SOURCE_GROUPS:
        matches = _merge_matches(
            _matching_pattern_texts(patterns, code),
            js_result.source_matches.get(source_kind, []),
            python_result.source_matches.get(source_kind, []),
        )
        if matches:
            detected_sources.add(source_kind)
            evidence.append(
                Evidence(
                    kind="static",
                    subject=skill_name,
                    predicate=predicate,
                    object=source_kind,
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
    credential_matches = _merge_matches(
        _matching_pattern_texts(_CREDENTIAL_PATTERNS, code),
        js_result.data_label_matches.get("credential", []),
        python_result.data_label_matches.get("credential", []),
    )
    if credential_matches:
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="has_data_label",
                object="credential",
                confidence=0.75,
                attrs={"matches": credential_matches[:5]},
            )
        )

    # --- PII / confidential data ---
    confidential_matches = _merge_matches(
        _matching_pattern_texts(_PII_PATTERNS, code),
        python_result.data_label_matches.get("confidential", []),
        python_result.data_label_matches.get("pii", []),
        python_result.data_label_matches.get("secret", []),
    )
    if confidential_matches:
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="has_data_label",
                object="confidential",
                confidence=0.65,
                attrs={"matches": confidential_matches[:5]},
            )
        )

    # --- Obfuscation / hiding hints ---
    obfuscation_matches = _merge_matches(
        _detect_text_obfuscation(code),
        js_result.obfuscation_matches,
        python_result.obfuscation_matches,
    )
    if obfuscation_matches:
        evidence.append(
            Evidence(
                kind="static",
                subject=skill_name,
                predicate="obfuscation_detected",
                object="encoded_or_hidden_literal",
                confidence=0.72,
                attrs={"matches": obfuscation_matches[:5]},
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
        "credential_access": bool(credential_matches),
    }
    for capability, present in capability_map.items():
        if present:
            evidence.append(
                Evidence(
                    kind="static",
                    subject=skill_name,
                    predicate="inferred_capability",
                    object=capability,
                    confidence=0.85,
                    attrs={"source": "static_pattern_match"},
                )
            )

    # --- Python AST source-to-sink summaries ---
    evidence.extend(python_result.evidence)
    return _dedupe_evidence(evidence)
