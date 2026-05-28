"""Baseline detectors for SkillGuardGraph experiments.

Each baseline uses a subset of evidence kinds or a simplified heuristic to
produce a RiskReport, enabling ablation-style comparison against the full
fusion pipeline.
"""
from __future__ import annotations

from collections import deque
from typing import Callable, Dict, List, Set

from .evidence_graph import EvidenceGraph
from .models import Decision, Evidence, Finding, RiskReport, Severity
from .scoring import aggregate_score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _filter_by_kind(evidence: List[Evidence], kinds: set[str]) -> List[Evidence]:
    """Return evidence items whose kind is in *kinds*."""
    return [e for e in evidence if e.kind in kinds]


def _score_to_decision(score: float) -> tuple[Severity, Decision]:
    """Map a 0-10 score to a (severity, decision) pair."""
    if score >= 7.0:
        return Severity.CRITICAL, Decision.DENY
    if score >= 4.0:
        return Severity.HIGH, Decision.HITL
    if score >= 1.0:
        return Severity.MEDIUM, Decision.DEGRADE
    return Severity.LOW, Decision.ALLOW


def _build_simple_report(
    findings: List[Finding],
    evidence_path: List[Evidence] | None = None,
) -> RiskReport:
    """Build a RiskReport from findings using the standard scoring path."""
    score = aggregate_score(findings)
    severity, decision = _score_to_decision(score)
    return RiskReport(
        risk=severity,
        decision=decision,
        findings=findings,
        score=score,
        evidence_path=evidence_path or [],
    )


def _reachable_via_flows(graph: EvidenceGraph, starts: Set[str], targets: Set[str], max_depth: int = 6) -> bool:
    """BFS reachability through flows_to edges in evidence."""
    if not starts or not targets:
        return False
    frontier = set(starts)
    seen = set(starts)
    for _ in range(max_depth):
        next_frontier: Set[str] = set()
        for node in frontier:
            for ev in graph.find(subject=node, predicate="flows_to"):
                if ev.object in targets:
                    return True
                if ev.object not in seen:
                    seen.add(ev.object)
                    next_frontier.add(ev.object)
        frontier = next_frontier
        if not frontier:
            break
    return False


# ---------------------------------------------------------------------------
# Predicates and objects actually produced by the analyzers
# ---------------------------------------------------------------------------

_STATIC_SOURCE_PREDICATE = "source_identified"
_STATIC_SINK_PREDICATE = "sink_identified"
_STATIC_SOURCE_OBJECTS = {"env_var", "file_read", "user_input", "database_query"}
_STATIC_SINK_OBJECTS = {"network_send", "file_write", "shell_exec", "email_send", "memory_write"}

_SUSPICIOUS_SANDBOX_BEHAVIORS = {
    "network_operation_detected",
    "file_write_operation_detected",
    "shell_exec_operation_detected",
    "destructive_annotation_present",
    "readonly_hint_with_write_code",
    "open_world_network_access",
}

# All predicates from all analyzers that indicate a suspicious signal
_ALL_SUSPICIOUS_PREDICATES = {
    # metadata / permission
    "requires_high_risk_scope",
    "contains_instruction_like_text",
    # static
    "source_identified",
    "sink_identified",
    "has_source_label",
    "is_high_privilege_call",
    "is_external_sink",
    "has_data_label",
    "inferred_capability",
    # sandbox
    "observes_behavior",
    # runtime
    "writes_persistent_store",
    "post_approval_drift",
    "high_risk_version_change",
    "flows_to",
}

_ALL_SUSPICIOUS_OBJECTS = {
    # source labels
    "untrusted",
    # data sensitivity
    "sensitive", "confidential", "credential", "pii", "secret",
    # static sink objects
    "network_send", "file_write", "shell_exec", "email_send", "memory_write",
    # static source objects
    "env_var", "file_read", "user_input",
    # scope objects
    "admin", "write", "delete", "export", "send",
}

_UNTRUSTED_SOURCE_LABELS = frozenset({
    "untrusted",
    "external_web",
    "external_email",
    "external_api_response",
    "synthetic_web_page",
    "synthetic_email",
    "synthetic_chat",
    "external",
})
_TRUSTDESC_RISKY_SINKS = {"network_send", "file_write", "shell_exec", "email_send", "memory_write"}
_TRUSTDESC_RISKY_CAPABILITIES = {
    "network_write",
    "file_write",
    "shell_exec",
    "email_send",
    "memory_write",
    "credential_access",
}
_SAST_RISKY_SINKS = {"network_send", "file_write", "shell_exec", "email_send"}
_EXTERNAL_SINK_KINDS = {"network_send", "email_send"}
_SENSITIVE_DATA_LABELS = {"credential", "confidential", "secret", "pii", "sensitive"}
_SANDBOX_BEHAVIOR_TO_SINK = {
    "network_operation_detected": "network_send",
    "file_write_operation_detected": "file_write",
    "shell_exec_operation_detected": "shell_exec",
}


def _dedupe_evidence_items(items: List[Evidence]) -> List[Evidence]:
    """Preserve order while removing duplicate evidence entries."""
    deduped: List[Evidence] = []
    seen: set[tuple[str, str, str, str, float, str]] = set()
    for ev in items:
        key = (ev.kind, ev.subject, ev.predicate, ev.object, ev.confidence, repr(ev.attrs))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ev)
    return deduped


def _evidence_for_subject_prefix(evidence: List[Evidence], subject: str) -> List[Evidence]:
    """Return evidence for *subject* and any derived sub-node subjects."""
    prefix = f"{subject}:"
    return [ev for ev in evidence if ev.subject == subject or ev.subject.startswith(prefix)]


def _shortest_flow_path(
    graph: EvidenceGraph,
    starts: Set[str],
    targets: Set[str],
    max_depth: int = 6,
) -> List[str] | None:
    """Return the shortest flows_to path from any start node to any target node."""
    if not starts or not targets:
        return None

    queue = deque((node, [node], 0) for node in sorted(starts))
    seen = set(starts)

    while queue:
        node, path, depth = queue.popleft()
        if node in targets:
            return path
        if depth >= max_depth:
            continue
        for edge in graph.find(subject=node, predicate="flows_to"):
            next_node = edge.object
            if next_node in seen:
                continue
            next_path = path + [next_node]
            if next_node in targets:
                return next_path
            seen.add(next_node)
            queue.append((next_node, next_path, depth + 1))
    return None


def _evidence_for_flow_path(graph: EvidenceGraph, path: List[str]) -> List[Evidence]:
    """Collect node and edge evidence for a flows_to path."""
    collected: List[Evidence] = []
    for idx, node in enumerate(path):
        collected.extend(graph.find(subject=node))
        if idx + 1 < len(path):
            collected.extend(graph.find(subject=node, predicate="flows_to", object=path[idx + 1]))
    return _dedupe_evidence_items(collected)


def _parse_source_sink_path(raw: str) -> tuple[str, str] | None:
    """Parse a `source_kind->sink_kind` summary."""
    if "->" not in raw:
        return None
    source_kind, sink_kind = raw.split("->", 1)
    return source_kind.strip(), sink_kind.strip()


# ---------------------------------------------------------------------------
# 1. metadata_only — uses metadata + permission + governance evidence only
#    Applies C1 (declared readonly vs write scope) and C5 (tainted approval)
# ---------------------------------------------------------------------------


def metadata_only(evidence: List[Evidence]) -> RiskReport:
    """Baseline: metadata-only analysis. Applies C1 and C5 constraints."""
    meta_evidence = _filter_by_kind(evidence, {"metadata", "permission", "governance"})
    if not meta_evidence:
        return _build_simple_report([])

    findings: List[Finding] = []
    graph = EvidenceGraph(evidence=meta_evidence)

    # C1: declared read-only but has write scopes
    read_only_subjects = graph.subjects_with("declares_capability", "read_only_or_low_risk")
    high_risk_subjects = graph.subjects_with("requires_high_risk_scope")
    overlap = read_only_subjects & high_risk_subjects
    if overlap:
        findings.append(Finding(
            constraint="C1_DECLARED_READONLY_BUT_WRITE_SCOPE",
            severity=Severity.HIGH,
            message=f"Metadata conflict: {len(overlap)} skill(s) claim read-only but request write scopes",
            evidence=meta_evidence,
            nodes=sorted(overlap),
        ))

    # C5: tainted approval text (check instruction-like text in manifest)
    tainted = graph.subjects_with("contains_instruction_like_text")
    if tainted:
        findings.append(Finding(
            constraint="C5_TAINTED_APPROVAL_TEXT",
            severity=Severity.MEDIUM,
            message=f"Manifest contains instruction-like text for {len(tainted)} skill(s)",
            evidence=[e for e in meta_evidence if e.subject in tainted],
            nodes=sorted(tainted),
        ))

    return _build_simple_report(findings, meta_evidence)


# ---------------------------------------------------------------------------
# 2. static_only — uses static analysis evidence only
#    Checks for source-sink patterns (taint-like)
# ---------------------------------------------------------------------------


def static_only(evidence: List[Evidence]) -> RiskReport:
    """Baseline: static analysis only. Checks source-sink patterns."""
    static_evidence = _filter_by_kind(evidence, {"static"})
    if not static_evidence:
        return _build_simple_report([])

    findings: List[Finding] = []
    graph = EvidenceGraph(evidence=static_evidence)

    # Look for sensitive sources connected to dangerous sinks
    sources = {
        e.subject for e in graph.evidence_with_predicate(_STATIC_SOURCE_PREDICATE)
        if e.object in _STATIC_SOURCE_OBJECTS
    }
    sinks = {
        e.subject for e in graph.evidence_with_predicate(_STATIC_SINK_PREDICATE)
        if e.object in _STATIC_SINK_OBJECTS
    }
    risky = sources & sinks

    if risky:
        findings.append(Finding(
            constraint="STATIC_SOURCE_SINK",
            severity=Severity.HIGH,
            message=f"Static analysis: {len(risky)} subject(s) have both sensitive sources and dangerous sinks",
            evidence=static_evidence,
            nodes=sorted(risky),
        ))

    # Flag high-risk sinks (shell, network send) even without explicit source patterns.
    # Having shell execution or network exfiltration code is suspicious on its own.
    high_risk_sinks = {
        e.subject for e in graph.evidence_with_predicate(_STATIC_SINK_PREDICATE)
        if e.object in {"shell_exec", "network_send"}
    }
    if high_risk_sinks:
        findings.append(Finding(
            constraint="STATIC_DANGEROUS_SINK",
            severity=Severity.HIGH,
            message=f"Static analysis: {len(high_risk_sinks)} subject(s) contain dangerous sinks (shell/network)",
            evidence=[e for e in static_evidence if e.subject in high_risk_sinks],
            nodes=sorted(high_risk_sinks),
        ))

    # Also flag credential access
    cred_subjects = {e.subject for e in graph.evidence_with_predicate("has_data_label") if e.object == "credential"}
    if cred_subjects:
        findings.append(Finding(
            constraint="STATIC_CREDENTIAL_ACCESS",
            severity=Severity.MEDIUM,
            message=f"Static analysis: {len(cred_subjects)} subject(s) access credentials",
            evidence=[e for e in static_evidence if e.subject in cred_subjects],
            nodes=sorted(cred_subjects),
        ))

    return _build_simple_report(findings, static_evidence)


# ---------------------------------------------------------------------------
# 3. sandbox_only — uses sandbox evidence only
# ---------------------------------------------------------------------------


def sandbox_only(evidence: List[Evidence]) -> RiskReport:
    """Baseline: sandbox-only analysis."""
    sandbox_evidence = _filter_by_kind(evidence, {"sandbox"})
    if not sandbox_evidence:
        return _build_simple_report([])

    findings: List[Finding] = []
    graph = EvidenceGraph(evidence=sandbox_evidence)

    # Check for sandbox-detected suspicious behaviors
    suspicious_subjects: set[str] = set()
    high_risk_behaviors: set[str] = set()
    for ev in sandbox_evidence:
        if ev.object in _SUSPICIOUS_SANDBOX_BEHAVIORS:
            suspicious_subjects.add(ev.subject)
            if ev.object in {"shell_exec_operation_detected", "network_operation_detected"}:
                high_risk_behaviors.add(ev.subject)

    if suspicious_subjects:
        # Escalate severity for high-risk behaviors or multiple detections
        if high_risk_behaviors or len(suspicious_subjects) >= 2:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        findings.append(Finding(
            constraint="SANDBOX_SUSPICIOUS_BEHAVIOR",
            severity=sev,
            message=f"Sandbox: {len(suspicious_subjects)} observation(s) flagged suspicious behavior",
            evidence=[e for e in sandbox_evidence if e.subject in suspicious_subjects],
            nodes=sorted(suspicious_subjects),
        ))

    return _build_simple_report(findings, sandbox_evidence)


# ---------------------------------------------------------------------------
# 4. runtime_only — uses runtime evidence only
#    Applies C2, C3, C6 constraints
# ---------------------------------------------------------------------------


def runtime_only(evidence: List[Evidence]) -> RiskReport:
    """Baseline: runtime-only analysis. Applies C2, C3, C6."""
    runtime_evidence = _filter_by_kind(evidence, {"runtime", "approval"})
    if not runtime_evidence:
        return _build_simple_report([])

    findings: List[Finding] = []
    graph = EvidenceGraph(evidence=runtime_evidence)

    # C2: untrusted source reaching high-privilege calls via flow edges
    untrusted = graph.subjects_with("has_source_label", "untrusted")
    high_priv = graph.subjects_with("is_high_privilege_call")
    if untrusted and high_priv and _reachable_via_flows(graph, untrusted, high_priv):
        findings.append(Finding(
            constraint="C2_UNTRUSTED_TO_HIGH_PRIVILEGE",
            severity=Severity.CRITICAL,
            message="Runtime: untrusted source reaches high-privilege tool call",
            evidence=runtime_evidence,
            nodes=sorted(untrusted | high_priv),
        ))

    # C3: sensitive data reaching external sinks via flow edges
    sensitive = graph.subjects_with("has_data_label")
    external_sinks = graph.subjects_with("is_external_sink")
    if sensitive and external_sinks and _reachable_via_flows(graph, sensitive, external_sinks):
        findings.append(Finding(
            constraint="C3_SENSITIVE_TO_EXTERNAL_SEQUENCE",
            severity=Severity.HIGH,
            message="Runtime: sensitive data flows to external sink",
            evidence=runtime_evidence,
            nodes=sorted(sensitive | external_sinks),
        ))

    # C6: untrusted source writing to persistent store via flow edges
    persistence_writers = graph.subjects_with("writes_persistent_store")
    if untrusted and persistence_writers and _reachable_via_flows(graph, untrusted, persistence_writers):
        findings.append(Finding(
            constraint="C6_UNTRUSTED_PERSISTENCE_WRITE",
            severity=Severity.HIGH,
            message="Runtime: untrusted source writes to persistent store",
            evidence=runtime_evidence,
            nodes=sorted(untrusted | persistence_writers),
        ))

    return _build_simple_report(findings, runtime_evidence)


# ---------------------------------------------------------------------------
# 5. naive_union — any single suspicious signal → high risk
# ---------------------------------------------------------------------------


def naive_union(evidence: List[Evidence]) -> RiskReport:
    """Baseline: naive union. If any evidence item is suspicious, flag as high risk.

    Heuristic: count evidence items that indicate risk.  If the count exceeds a
    threshold, the report is escalated.
    """
    if not evidence:
        return _build_simple_report([])

    suspicious_signals = 0
    suspicious_evidence: List[Evidence] = []

    for ev in evidence:
        is_suspicious = False
        if ev.predicate in _ALL_SUSPICIOUS_PREDICATES:
            is_suspicious = True
        if ev.object in _ALL_SUSPICIOUS_OBJECTS:
            is_suspicious = True
        # Sandbox behaviors: only count suspicious ones
        if ev.kind == "sandbox" and ev.object in _SUSPICIOUS_SANDBOX_BEHAVIORS:
            is_suspicious = True
        if is_suspicious:
            suspicious_signals += 1
            suspicious_evidence.append(ev)

    findings: List[Finding] = []
    if suspicious_signals > 0:
        # Threshold: any suspicious signal → medium; 3+ → high; 5+ → critical
        if suspicious_signals >= 5:
            sev = Severity.CRITICAL
        elif suspicious_signals >= 3:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        findings.append(Finding(
            constraint="NAIVE_UNION",
            severity=sev,
            message=f"Naive union: {suspicious_signals} suspicious signal(s) detected",
            evidence=suspicious_evidence,
        ))

    return _build_simple_report(findings, suspicious_evidence)


# ---------------------------------------------------------------------------
# 6. weighted_voting — weighted sum of suspicious signals vs threshold
# ---------------------------------------------------------------------------

_WEIGHTS: Dict[str, float] = {
    "metadata": 0.15,
    "permission": 0.15,
    "static": 0.20,
    "sandbox": 0.25,
    "runtime": 0.30,
    "approval": 0.30,
    "governance": 0.10,
}


def weighted_voting(evidence: List[Evidence]) -> RiskReport:
    """Baseline: weighted voting across evidence kinds.

    Each evidence kind contributes a weight.  The weighted sum of suspicious
    items (items whose predicate or object matches a risk heuristic) is
    compared against thresholds to determine the decision.
    """
    if not evidence:
        return _build_simple_report([])

    # Accumulate per-kind suspicious counts
    kind_counts: Dict[str, int] = {}
    kind_suspicious: Dict[str, List[Evidence]] = {}
    for ev in evidence:
        is_suspicious = (
            ev.predicate in _ALL_SUSPICIOUS_PREDICATES
            or ev.object in _ALL_SUSPICIOUS_OBJECTS
            or (ev.kind == "sandbox" and ev.object in _SUSPICIOUS_SANDBOX_BEHAVIORS)
        )
        if is_suspicious:
            kind_counts[ev.kind] = kind_counts.get(ev.kind, 0) + 1
            kind_suspicious.setdefault(ev.kind, []).append(ev)

    weighted_sum = sum(
        kind_counts.get(kind, 0) * weight
        for kind, weight in _WEIGHTS.items()
    )

    findings: List[Finding] = []
    all_suspicious: List[Evidence] = []
    for items in kind_suspicious.values():
        all_suspicious.extend(items)

    if weighted_sum > 0:
        if weighted_sum >= 3.0:
            sev = Severity.CRITICAL
        elif weighted_sum >= 1.5:
            sev = Severity.HIGH
        else:
            sev = Severity.MEDIUM
        findings.append(Finding(
            constraint="WEIGHTED_VOTING",
            severity=sev,
            message=f"Weighted voting: score={weighted_sum:.2f} from {sum(kind_counts.values())} suspicious signal(s)",
            evidence=all_suspicious,
        ))

    return _build_simple_report(findings, all_suspicious)


# ---------------------------------------------------------------------------
# 7. llm_judge_stub — simulates LLM judge heuristic
# ---------------------------------------------------------------------------


def llm_judge_stub(evidence: List[Evidence]) -> RiskReport:
    """Baseline: simulated LLM judge.

    This is a SIMULATION, not an actual LLM call.  The heuristic mimics what
    an LLM judge might do: flag high-risk when multiple distinct evidence
    *kinds* report suspicious signals (cross-layer corroboration).
    """
    if not evidence:
        return _build_simple_report([])

    # Count how many distinct evidence kinds have at least one suspicious item
    suspicious_kinds: set[str] = set()
    suspicious_evidence: List[Evidence] = []
    for ev in evidence:
        is_suspicious = (
            ev.predicate in _ALL_SUSPICIOUS_PREDICATES
            or ev.object in _ALL_SUSPICIOUS_OBJECTS
            or (ev.kind == "sandbox" and ev.object in _SUSPICIOUS_SANDBOX_BEHAVIORS)
        )
        if is_suspicious:
            suspicious_kinds.add(ev.kind)
            suspicious_evidence.append(ev)

    findings: List[Finding] = []

    if len(suspicious_kinds) >= 3:
        sev = Severity.CRITICAL
    elif len(suspicious_kinds) >= 2:
        sev = Severity.HIGH
    elif len(suspicious_kinds) >= 1:
        sev = Severity.MEDIUM
    else:
        sev = Severity.LOW

    if suspicious_kinds:
        findings.append(Finding(
            constraint="LLM_JUDGE_STUB",
            severity=sev,
            message=f"LLM judge (stub): {len(suspicious_kinds)} evidence kind(s) report suspicious signals ({', '.join(sorted(suspicious_kinds))})",
            evidence=suspicious_evidence,
        ))

    return _build_simple_report(findings, suspicious_evidence)

# ---------------------------------------------------------------------------
# 8. trustdesc_style — manifest-description vs implementation consistency
# ---------------------------------------------------------------------------


def trustdesc_style(evidence: List[Evidence]) -> RiskReport:
    """Baseline: compare low-risk manifest claims against implemented behavior."""
    meta_evidence = _filter_by_kind(evidence, {"metadata", "permission"})
    static_evidence = _filter_by_kind(evidence, {"static"})
    if not meta_evidence or not static_evidence:
        return _build_simple_report([])

    meta_graph = EvidenceGraph(evidence=meta_evidence)
    findings: List[Finding] = []
    supporting: List[Evidence] = []

    low_risk_claims = meta_graph.subjects_with("declares_capability", "read_only_or_low_risk")
    low_risk_claims |= meta_graph.subjects_with("annotation_claims", "read_only")

    for skill in sorted(low_risk_claims):
        skill_meta = meta_graph.evidence_for_subject(skill)
        skill_static = _evidence_for_subject_prefix(static_evidence, skill)
        if not skill_static:
            continue

        risky_impl = {
            ev.object
            for ev in skill_static
            if (ev.predicate == "sink_identified" and ev.object in _TRUSTDESC_RISKY_SINKS)
            or (ev.predicate == "inferred_capability" and ev.object in _TRUSTDESC_RISKY_CAPABILITIES)
        }
        has_high_priv = any(ev.predicate == "is_high_privilege_call" for ev in skill_static)
        has_external_sink = any(ev.predicate == "is_external_sink" for ev in skill_static)
        inferred_capabilities = {ev.object for ev in skill_static if ev.predicate == "inferred_capability"}
        complex_surface = len(inferred_capabilities) >= 4

        consistency = 1.0
        if risky_impl:
            consistency -= 0.45
        if has_high_priv or has_external_sink:
            consistency -= 0.25
        consistency -= 0.12 * max(0, len(inferred_capabilities) - 1)
        consistency = max(0.0, round(consistency, 2))

        if not (risky_impl or has_high_priv or has_external_sink or complex_surface):
            continue

        implemented = sorted(risky_impl) or sorted(inferred_capabilities)[:3]
        if complex_surface and "complex_capability_mix" not in implemented:
            implemented.append("complex_capability_mix")

        related = _dedupe_evidence_items(skill_meta + skill_static)
        findings.append(Finding(
            constraint="TRUSTDESC_DESCRIPTION_MISMATCH",
            severity=Severity.HIGH,
            message=(
                f"TRUSTDESC-style mismatch: {skill} advertises low-risk/read-only behavior "
                f"but implements {', '.join(implemented[:4])} "
                f"(consistency={consistency:.2f})"
            ),
            evidence=related,
            nodes=[skill],
        ))
        supporting.extend(related)

    return _build_simple_report(findings, _dedupe_evidence_items(supporting))


# ---------------------------------------------------------------------------
# 9. sast_style — strict source-sink rules
# ---------------------------------------------------------------------------


def sast_style(evidence: List[Evidence]) -> RiskReport:
    """Baseline: Semgrep/SAST-style source-sink pair counting."""
    static_evidence = _filter_by_kind(evidence, {"static"})
    runtime_evidence = _filter_by_kind(evidence, {"runtime"})
    sandbox_evidence = _filter_by_kind(evidence, {"sandbox"})
    pair_support: Dict[tuple[str, str, str], List[Evidence]] = {}

    if static_evidence:
        static_graph = EvidenceGraph(evidence=static_evidence)

        for ev in static_graph.evidence_with_predicate("source_sink_path"):
            parsed = _parse_source_sink_path(ev.object)
            if parsed is None:
                continue
            source_kind, sink_kind = parsed
            if source_kind in _STATIC_SOURCE_OBJECTS and sink_kind in _SAST_RISKY_SINKS:
                support = static_graph.evidence_for_subject(ev.subject) + [ev]
                pair_support[(source_kind, sink_kind, ev.subject)] = _dedupe_evidence_items(support)

        shared_subjects = static_graph.subjects_with(_STATIC_SOURCE_PREDICATE) & static_graph.subjects_with(_STATIC_SINK_PREDICATE)
        for subject in sorted(shared_subjects):
            source_kinds = static_graph.objects_of(subject, _STATIC_SOURCE_PREDICATE) & _STATIC_SOURCE_OBJECTS
            sink_kinds = static_graph.objects_of(subject, _STATIC_SINK_PREDICATE) & _SAST_RISKY_SINKS
            if not source_kinds or not sink_kinds:
                continue
            related = static_graph.evidence_for_subject(subject)
            for source_kind in sorted(source_kinds):
                for sink_kind in sorted(sink_kinds):
                    pair_support.setdefault((source_kind, sink_kind, subject), related)

        source_nodes: Dict[str, str] = {}
        sink_nodes: Dict[str, str] = {}
        for ev in static_evidence:
            if ev.predicate == "has_source_label":
                source_kind = str(ev.attrs.get("source_kind", "")).lower()
                if source_kind in _STATIC_SOURCE_OBJECTS:
                    source_nodes[ev.subject] = source_kind
            elif ev.predicate == _STATIC_SOURCE_PREDICATE and ev.object in _STATIC_SOURCE_OBJECTS:
                source_nodes.setdefault(ev.subject, ev.object)

            if ev.predicate == _STATIC_SINK_PREDICATE and ev.object in _SAST_RISKY_SINKS:
                sink_nodes[ev.subject] = ev.object
            elif ev.predicate == "is_external_sink":
                sink_nodes.setdefault(ev.subject, "network_send" if ev.object == "network" else "email_send")

        for source_node, source_kind in source_nodes.items():
            for flow_ev in static_graph.find(subject=source_node, predicate="flows_to"):
                sink_kind = sink_nodes.get(flow_ev.object)
                if sink_kind is None:
                    continue
                related = (
                    static_graph.evidence_for_subject(source_node)
                    + [flow_ev]
                    + static_graph.evidence_for_subject(flow_ev.object)
                )
                pair_support.setdefault(
                    (source_kind, sink_kind, f"{source_node}->{flow_ev.object}"),
                    _dedupe_evidence_items(related),
                )

    evidence_mode = "static"
    if not pair_support and runtime_evidence:
        runtime_graph = EvidenceGraph(evidence=runtime_evidence)
        runtime_source_nodes: Dict[str, str] = {}
        runtime_sink_nodes: Dict[str, str] = {}

        for ev in runtime_evidence:
            if ev.predicate == "has_source_label" and ev.object in _UNTRUSTED_SOURCE_LABELS:
                runtime_source_nodes[ev.subject] = "user_input"
            elif ev.predicate == "has_data_label" and ev.object in _SENSITIVE_DATA_LABELS:
                runtime_source_nodes.setdefault(ev.subject, "database_query")

            if ev.predicate == "is_external_sink":
                runtime_sink_nodes[ev.subject] = "network_send" if ev.object == "network" else "email_send"
            elif ev.predicate == "is_high_privilege_call":
                runtime_sink_nodes.setdefault(ev.subject, "shell_exec")
            elif ev.predicate == "writes_persistent_store":
                runtime_sink_nodes.setdefault(ev.subject, "file_write")

        for source_node, source_kind in runtime_source_nodes.items():
            path = _shortest_flow_path(runtime_graph, {source_node}, set(runtime_sink_nodes), max_depth=8)
            if path is None:
                continue
            sink_kind = runtime_sink_nodes.get(path[-1])
            if sink_kind is None or sink_kind not in _SAST_RISKY_SINKS:
                continue
            pair_support[(source_kind, sink_kind, "->".join(path))] = _evidence_for_flow_path(runtime_graph, path)
        evidence_mode = "runtime_fallback"

    if not pair_support and static_evidence and sandbox_evidence:
        source_by_skill: Dict[str, Set[str]] = {}
        for ev in static_evidence:
            if ev.predicate == _STATIC_SOURCE_PREDICATE and ev.object in _STATIC_SOURCE_OBJECTS:
                source_by_skill.setdefault(ev.subject, set()).add(ev.object)
            elif ev.predicate == "has_source_label":
                source_kind = str(ev.attrs.get("source_kind", "")).lower()
                if source_kind in _STATIC_SOURCE_OBJECTS:
                    root_subject = ev.subject.split(":static_", 1)[0]
                    source_by_skill.setdefault(root_subject, set()).add(source_kind)

        sink_by_skill: Dict[str, Set[str]] = {}
        for ev in sandbox_evidence:
            if ev.predicate != "observes_behavior":
                continue
            sink_kind = _SANDBOX_BEHAVIOR_TO_SINK.get(ev.object)
            if sink_kind is not None:
                sink_by_skill.setdefault(ev.subject, set()).add(sink_kind)

        for skill in sorted(source_by_skill.keys() & sink_by_skill.keys()):
            related = _evidence_for_subject_prefix(static_evidence, skill) + [ev for ev in sandbox_evidence if ev.subject == skill]
            for source_kind in sorted(source_by_skill[skill]):
                for sink_kind in sorted(sink_by_skill[skill]):
                    pair_support[(source_kind, sink_kind, skill)] = _dedupe_evidence_items(related)
        evidence_mode = "sandbox_fallback"

    pair_count = len(pair_support)
    if pair_count == 0:
        return _build_simple_report([])

    severity = Severity.HIGH if pair_count >= 2 else Severity.MEDIUM
    supporting: List[Evidence] = []
    for items in pair_support.values():
        supporting.extend(items)
    related = _dedupe_evidence_items(supporting)

    return _build_simple_report(
        [
            Finding(
                constraint="SAST_SOURCE_SINK_RULES",
                severity=severity,
                message=f"SAST-style taint rules found {pair_count} risky source-sink pair(s) via {evidence_mode}",
                evidence=related,
                nodes=sorted({ev.subject for ev in related}),
            )
        ],
        related,
    )


# ---------------------------------------------------------------------------
# 10. taint_dataflow — simplified cross-layer dataflow scoring
# ---------------------------------------------------------------------------


def taint_dataflow(evidence: List[Evidence]) -> RiskReport:
    """Baseline: simplified taint/dataflow analysis across static + runtime evidence."""
    if not evidence:
        return _build_simple_report([])

    graph = EvidenceGraph(evidence=evidence)
    static_evidence = _filter_by_kind(evidence, {"static"})
    meta_evidence = _filter_by_kind(evidence, {"metadata", "permission"})

    low_risk_claims = set()
    low_risk_claims |= {ev.subject for ev in meta_evidence if ev.predicate == "declares_capability" and ev.object == "read_only_or_low_risk"}
    low_risk_claims |= {ev.subject for ev in meta_evidence if ev.predicate == "annotation_claims" and ev.object == "read_only"}
    metadata_mismatch_support: List[Evidence] = []
    for skill in sorted(low_risk_claims):
        skill_meta = [ev for ev in meta_evidence if ev.subject == skill]
        skill_static = _evidence_for_subject_prefix(static_evidence, skill)
        if any(
            (ev.predicate == "sink_identified" and ev.object in _TRUSTDESC_RISKY_SINKS)
            or ev.predicate in {"is_external_sink", "is_high_privilege_call"}
            for ev in skill_static
        ):
            metadata_mismatch_support = _dedupe_evidence_items(skill_meta + skill_static)
            break
    has_metadata_mismatch = bool(metadata_mismatch_support)

    external_sinks = {
        ev.subject
        for ev in evidence
        if ev.predicate == "is_external_sink"
        or (ev.predicate == "sink_identified" and ev.object in _EXTERNAL_SINK_KINDS)
    }
    untrusted_sources = {
        ev.subject
        for ev in evidence
        if ev.predicate == "has_source_label" and ev.object in _UNTRUSTED_SOURCE_LABELS
    }
    sensitive_sources = {
        ev.subject
        for ev in evidence
        if ev.predicate == "has_data_label" and ev.object in _SENSITIVE_DATA_LABELS
    }

    best_findings: Dict[str, tuple[float, Finding]] = {}

    def consider_candidate(
        key: str,
        constraint: str,
        message_prefix: str,
        source_weight: float,
        path_len: int,
        related: List[Evidence],
        nodes: List[str],
    ) -> None:
        score = source_weight + 0.30 + min(0.20, 0.05 * max(path_len, 1))
        if has_metadata_mismatch:
            score += 0.10
            related = _dedupe_evidence_items(related + metadata_mismatch_support)
        severity = Severity.HIGH if score >= 0.80 else Severity.MEDIUM
        suffix = " with metadata mismatch" if has_metadata_mismatch else ""
        finding = Finding(
            constraint=constraint,
            severity=severity,
            message=f"{message_prefix} over {path_len} hop(s) (score={score:.2f}{suffix})",
            evidence=related,
            nodes=nodes,
        )
        current = best_findings.get(key)
        if current is None or score > current[0]:
            best_findings[key] = (score, finding)

    untrusted_path = _shortest_flow_path(graph, untrusted_sources, external_sinks)
    if untrusted_path is not None:
        related = _evidence_for_flow_path(graph, untrusted_path)
        consider_candidate(
            key="untrusted_external",
            constraint="TAINT_DATAFLOW_UNTRUSTED_EXTERNAL",
            message_prefix="Untrusted source reaches external sink",
            source_weight=0.30,
            path_len=len(untrusted_path) - 1,
            related=related,
            nodes=untrusted_path,
        )

    sensitive_path = _shortest_flow_path(graph, sensitive_sources, external_sinks)
    if sensitive_path is not None:
        related = _evidence_for_flow_path(graph, sensitive_path)
        consider_candidate(
            key="sensitive_external",
            constraint="TAINT_DATAFLOW_SENSITIVE_EXTERNAL",
            message_prefix="Sensitive data reaches external sink",
            source_weight=0.45,
            path_len=len(sensitive_path) - 1,
            related=related,
            nodes=sensitive_path,
        )

    for ev in static_evidence:
        if ev.predicate != "source_sink_path":
            continue
        parsed = _parse_source_sink_path(ev.object)
        if parsed is None:
            continue
        source_kind, sink_kind = parsed
        if sink_kind not in _EXTERNAL_SINK_KINDS:
            continue
        related = _dedupe_evidence_items(_evidence_for_subject_prefix(static_evidence, ev.subject) + [ev])
        if source_kind in {"env_var", "user_input"}:
            consider_candidate(
                key="untrusted_external",
                constraint="TAINT_DATAFLOW_UNTRUSTED_EXTERNAL",
                message_prefix="Untrusted source reaches external sink",
                source_weight=0.30,
                path_len=2,
                related=related,
                nodes=[ev.subject],
            )
        if source_kind in {"file_read", "database_query"}:
            consider_candidate(
                key="sensitive_external",
                constraint="TAINT_DATAFLOW_SENSITIVE_EXTERNAL",
                message_prefix="Sensitive data reaches external sink",
                source_weight=0.45,
                path_len=2,
                related=related,
                nodes=[ev.subject],
            )

    findings = [item[1] for item in best_findings.values()]
    if not findings:
        return _build_simple_report([])

    supporting: List[Evidence] = []
    for finding in findings:
        supporting.extend(finding.evidence)
    return _build_simple_report(findings, _dedupe_evidence_items(supporting))


# ---------------------------------------------------------------------------
# 11. mcpshield_style — runtime trust calibration
# ---------------------------------------------------------------------------


def mcpshield_style(evidence: List[Evidence]) -> RiskReport:
    """Baseline: MCPShield-style trust calibration from runtime and governance signals."""
    sandbox_evidence = _filter_by_kind(evidence, {"sandbox"})
    runtime_evidence = _filter_by_kind(evidence, {"runtime"})
    governance_evidence = _filter_by_kind(evidence, {"governance"})

    trust_score = 1.0
    supporting: List[Evidence] = []
    penalties: List[str] = []

    sandbox_penalties = {
        "network_operation_detected": 0.3,
        "file_write_operation_detected": 0.2,
        "shell_exec_operation_detected": 0.4,
    }
    for behavior, penalty in sandbox_penalties.items():
        matched = [ev for ev in sandbox_evidence if ev.predicate == "observes_behavior" and ev.object == behavior]
        if matched:
            trust_score -= penalty
            supporting.extend(matched)
            penalties.append(behavior)

    untrusted_runtime = [
        ev for ev in runtime_evidence
        if ev.predicate == "has_source_label" and ev.object in _UNTRUSTED_SOURCE_LABELS
    ]
    if untrusted_runtime:
        trust_score -= 0.2
        supporting.extend(untrusted_runtime)
        penalties.append("untrusted_source_label")

    missing_signature = [ev for ev in governance_evidence if ev.predicate == "signed" and ev.object == "false"]
    if missing_signature:
        trust_score -= 0.1
        supporting.extend(missing_signature)
        penalties.append("missing_signature")

    publisher_evidence = [ev for ev in governance_evidence if ev.predicate == "published_by"]
    trusted_server = any(ev.predicate == "has_trust_label" and ev.object == "trusted_server" for ev in evidence)
    if publisher_evidence and not trusted_server:
        trust_score -= 0.1
        supporting.extend(publisher_evidence)
        penalties.append("untrusted_publisher")

    trust_score = max(0.0, round(trust_score, 2))
    if trust_score >= 0.7:
        return _build_simple_report([])

    severity = Severity.HIGH if trust_score < 0.5 else Severity.MEDIUM
    related = _dedupe_evidence_items(supporting)
    return _build_simple_report(
        [
            Finding(
                constraint="MCPSHIELD_TRUST_CALIBRATION",
                severity=severity,
                message=(
                    f"MCPShield-style trust calibration dropped to {trust_score:.2f} "
                    f"from signals: {', '.join(penalties)}"
                ),
                evidence=related,
                nodes=sorted({ev.subject for ev in related}),
            )
        ],
        related,
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


BASELINES: Dict[str, Callable[[List[Evidence]], RiskReport]] = {
    "metadata_only": metadata_only,
    "static_only": static_only,
    "sandbox_only": sandbox_only,
    "runtime_only": runtime_only,
    "naive_union": naive_union,
    "weighted_voting": weighted_voting,
    "llm_judge": llm_judge_stub,
    "trustdesc_style": trustdesc_style,
    "sast_style": sast_style,
    "taint_dataflow": taint_dataflow,
    "mcpshield_style": mcpshield_style,
}


def run_all_baselines(evidence: List[Evidence]) -> Dict[str, RiskReport]:
    """Run all baselines on the same evidence."""
    return {name: fn(evidence) for name, fn in BASELINES.items()}
