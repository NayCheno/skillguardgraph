"""Baseline detectors for SkillGuardGraph experiments.

Each baseline uses a subset of evidence kinds or a simplified heuristic to
produce a RiskReport, enabling ablation-style comparison against the full
fusion pipeline.
"""
from __future__ import annotations

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
}


def run_all_baselines(evidence: List[Evidence]) -> Dict[str, RiskReport]:
    """Run all baselines on the same evidence."""
    return {name: fn(evidence) for name, fn in BASELINES.items()}
