from __future__ import annotations

from typing import List, Set

from .evidence_graph import EvidenceGraph
from .models import Decision, Evidence, Finding, RiskReport, Severity

HIGH_RISK_SCOPES = {"write", "delete", "export", "send", "admin", "modify"}


def evaluate(graph: EvidenceGraph) -> RiskReport:
    findings: List[Finding] = []
    findings.extend(_c1_declared_readonly_but_write_scope(graph))
    findings.extend(_c2_untrusted_to_high_privilege(graph))
    findings.extend(_c3_sensitive_to_external_sequence(graph))
    findings.extend(_c4_post_approval_drift(graph))
    findings.extend(_c5_tainted_approval_text(graph))
    findings.extend(_c6_untrusted_persistence_write(graph))

    if any(f.severity == Severity.CRITICAL for f in findings):
        return RiskReport(Severity.CRITICAL, Decision.DENY, findings)
    if any(f.severity == Severity.HIGH for f in findings):
        return RiskReport(Severity.HIGH, Decision.HITL, findings)
    if any(f.severity == Severity.MEDIUM for f in findings):
        return RiskReport(Severity.MEDIUM, Decision.DEGRADE, findings)
    return RiskReport(Severity.LOW, Decision.ALLOW, findings)


def _c1_declared_readonly_but_write_scope(graph: EvidenceGraph) -> List[Finding]:
    findings: List[Finding] = []
    readonly_subjects: Set[str] = {
        e.subject
        for e in graph.evidence
        if (
            (e.predicate == "declares_capability" and e.object == "read_only_or_low_risk")
            or (e.predicate == "annotation_claims" and e.object == "read_only")
        )
    }
    for subject in readonly_subjects:
        scope_evidence = [
            e
            for e in graph.find(subject=subject)
            if e.predicate in {"requires_scope", "requires_high_risk_scope"}
            and any(scope in e.object for scope in HIGH_RISK_SCOPES)
        ]
        if scope_evidence:
            supporting = graph.find(subject=subject, predicate="declares_capability") + graph.find(
                subject=subject, predicate="annotation_claims"
            ) + scope_evidence
            findings.append(
                Finding(
                    constraint="C1_DECLARED_READONLY_BUT_WRITE_SCOPE",
                    severity=Severity.HIGH,
                    decision=Decision.HITL,
                    summary="Skill declares read-only or low-risk behavior but requests write/export/admin-like scope.",
                    evidence=supporting,
                )
            )
    return findings


def _reachable(graph: EvidenceGraph, starts: Set[str], targets: Set[str], max_depth: int = 6) -> bool:
    frontier = set(starts)
    seen = set(starts)
    for _ in range(max_depth):
        next_frontier: Set[str] = set()
        for node in frontier:
            for edge in graph.find(subject=node, predicate="flows_to"):
                if edge.object in targets:
                    return True
                if edge.object not in seen:
                    seen.add(edge.object)
                    next_frontier.add(edge.object)
        frontier = next_frontier
        if not frontier:
            break
    return False


def _path_evidence(graph: EvidenceGraph, starts: Set[str], targets: Set[str]) -> List[Evidence]:
    out: List[Evidence] = []
    for start in starts:
        out.extend(graph.find(subject=start, predicate="has_source_label"))
        out.extend(graph.find(subject=start, predicate="has_data_label"))
        out.extend(graph.find(subject=start, predicate="flows_to"))
    for target in targets:
        out.extend(graph.find(subject=target))
    return out[:20]


def _c2_untrusted_to_high_privilege(graph: EvidenceGraph) -> List[Finding]:
    untrusted = graph.subjects_with("has_source_label", "untrusted")
    high_priv = graph.subjects_with("is_high_privilege_call")
    if untrusted and high_priv and _reachable(graph, untrusted, high_priv):
        return [
            Finding(
                constraint="C2_UNTRUSTED_TO_HIGH_PRIVILEGE",
                severity=Severity.HIGH,
                decision=Decision.HITL,
                summary="Untrusted source reaches a high-privilege tool call through runtime provenance.",
                evidence=_path_evidence(graph, untrusted, high_priv),
            )
        ]
    return []


def _c3_sensitive_to_external_sequence(graph: EvidenceGraph) -> List[Finding]:
    sensitive = {
        e.subject
        for e in graph.find(predicate="has_data_label")
        if e.object in {"confidential", "secret", "pii", "credential"}
    }
    external = graph.subjects_with("is_external_sink")
    if sensitive and external and _reachable(graph, sensitive, external):
        return [
            Finding(
                constraint="C3_SENSITIVE_TO_EXTERNAL_SEQUENCE",
                severity=Severity.CRITICAL,
                decision=Decision.DENY,
                summary="Sensitive data reaches an external sink through a tool-call sequence.",
                evidence=_path_evidence(graph, sensitive, external),
            )
        ]
    return []


def _c4_post_approval_drift(graph: EvidenceGraph) -> List[Finding]:
    findings: List[Finding] = []
    for drift in graph.find(predicate="post_approval_drift", object="high"):
        findings.append(
            Finding(
                constraint="C4_POST_APPROVAL_DRIFT",
                severity=Severity.HIGH,
                decision=Decision.QUARANTINE,
                summary="A previously approved skill version shows high-risk post-approval behavior drift.",
                evidence=[drift],
            )
        )
    return findings


def _c5_tainted_approval_text(graph: EvidenceGraph) -> List[Finding]:
    findings: List[Finding] = []
    for approval in graph.find(predicate="approval_text_lineage", object="untrusted_context_only"):
        findings.append(
            Finding(
                constraint="C5_TAINTED_APPROVAL_TEXT",
                severity=Severity.HIGH,
                decision=Decision.HITL,
                summary="Approval dialog is derived only from untrusted/model context instead of execution-layer facts.",
                evidence=[approval],
            )
        )
    return findings


def _c6_untrusted_persistence_write(graph: EvidenceGraph) -> List[Finding]:
    untrusted = graph.subjects_with("has_source_label", "untrusted")
    persistent = graph.subjects_with("writes_persistent_store")
    if untrusted and persistent and _reachable(graph, untrusted, persistent):
        return [
            Finding(
                constraint="C6_UNTRUSTED_PERSISTENCE_WRITE",
                severity=Severity.HIGH,
                decision=Decision.DENY,
                summary="Untrusted source reaches a persistent store such as memory/config/hooks/policy store.",
                evidence=_path_evidence(graph, untrusted, persistent),
            )
        ]
    return []
