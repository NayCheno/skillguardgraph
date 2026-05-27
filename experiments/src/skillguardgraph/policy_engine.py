"""Policy engine for SkillGuardGraph.

Evaluates cross-layer constraints C1-C7 against the evidence graph.
"""
from __future__ import annotations

from typing import List, Set

from .evidence_graph import EvidenceGraph
from .models import Decision, Evidence, Finding, RiskReport, Severity
from .scoring import aggregate_score

HIGH_RISK_SCOPES = {"write", "delete", "export", "send", "admin", "modify"}

# Source labels that indicate untrusted / external origins
_UNTRUSTED_LABELS = frozenset({
    "untrusted", "external_web", "external_email", "external_api_response",
    "synthetic_web_page", "synthetic_email", "synthetic_chat", "external",
})


def evaluate(graph: EvidenceGraph) -> RiskReport:
    findings: List[Finding] = []
    findings.extend(_c1_declared_readonly_but_write_scope(graph))
    findings.extend(_c2_untrusted_to_high_privilege(graph))
    findings.extend(_c3_sensitive_to_external_sequence(graph))
    findings.extend(_c4_post_approval_drift(graph))
    findings.extend(_c5_tainted_approval_text(graph))
    findings.extend(_c6_untrusted_persistence_write(graph))
    findings.extend(_c7_least_privilege_scope(graph))

    score = aggregate_score(findings)

    if any(f.severity == Severity.CRITICAL for f in findings):
        return RiskReport(Severity.CRITICAL, Decision.DENY, findings, score=score)
    if any(f.severity == Severity.HIGH for f in findings):
        return RiskReport(Severity.HIGH, Decision.HITL, findings, score=score)
    if any(f.severity == Severity.MEDIUM for f in findings):
        return RiskReport(Severity.MEDIUM, Decision.DEGRADE, findings, score=score)
    return RiskReport(Severity.LOW, Decision.ALLOW, findings, score=score)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _untrusted_subjects(graph: EvidenceGraph) -> Set[str]:
    """Return subjects with untrusted/external source labels."""
    return {
        e.subject for e in graph.evidence
        if e.predicate == "has_source_label" and e.object in _UNTRUSTED_LABELS
    }


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


# ---------------------------------------------------------------------------
# C1: Declaration–Implementation–Permission Consistency
# ---------------------------------------------------------------------------


def _c1_declared_readonly_but_write_scope(graph: EvidenceGraph) -> List[Finding]:
    """C1: declared capability conflicts with granted permission scope.

    Flags MEDIUM when scope mismatch exists alone.
    Flags HIGH when there's also evidence of actual write/network activity.
    """
    findings: List[Finding] = []
    readonly_subjects: Set[str] = {
        e.subject for e in graph.evidence
        if (
            (e.predicate == "declares_capability" and e.object == "read_only_or_low_risk")
            or (e.predicate == "annotation_claims" and e.object == "read_only")
        )
    }

    write_evidence_predicates = {
        "sink_identified", "is_external_sink", "sandbox_observed_write",
        "sandbox_observed_network", "sandbox_observed_shell",
        "writes_persistent_store", "flows_to",
    }
    has_actual_write = any(e.predicate in write_evidence_predicates for e in graph.evidence)

    for subject in readonly_subjects:
        scope_evidence = [
            e for e in graph.find(subject=subject)
            if e.predicate in {"requires_scope", "requires_high_risk_scope"}
            and any(scope in e.object for scope in HIGH_RISK_SCOPES)
        ]
        if scope_evidence:
            supporting = (
                graph.find(subject=subject, predicate="declares_capability")
                + graph.find(subject=subject, predicate="annotation_claims")
                + scope_evidence
            )
            severity = Severity.HIGH if has_actual_write else Severity.MEDIUM
            findings.append(Finding(
                constraint="C1_DECLARED_READONLY_BUT_WRITE_SCOPE",
                severity=severity,
                message="Skill declares read-only or low-risk behavior but requests write/export/admin-like scope.",
                evidence=supporting,
            ))
    return findings


# ---------------------------------------------------------------------------
# C2: Source-Aware High-Privilege Flow
# ---------------------------------------------------------------------------


def _c2_untrusted_to_high_privilege(graph: EvidenceGraph) -> List[Finding]:
    """C2: untrusted/external source reaches a high-privilege tool call."""
    untrusted = _untrusted_subjects(graph)
    high_priv = graph.subjects_with("is_high_privilege_call")
    if untrusted and high_priv and _reachable(graph, untrusted, high_priv):
        return [Finding(
            constraint="C2_UNTRUSTED_TO_HIGH_PRIVILEGE",
            severity=Severity.HIGH,
            message="Untrusted source reaches a high-privilege tool call through runtime provenance.",
            evidence=_path_evidence(graph, untrusted, high_priv),
        )]
    return []


# ---------------------------------------------------------------------------
# C3: Cross-Tool Exfiltration Sequence
# ---------------------------------------------------------------------------


def _c3_sensitive_to_external_sequence(graph: EvidenceGraph) -> List[Finding]:
    """C3: sensitive data reaches an external sink through a tool-call sequence."""
    sensitive = {
        e.subject for e in graph.find(predicate="has_data_label")
        if e.object in {"confidential", "secret", "pii", "credential"}
    }
    external = graph.subjects_with("is_external_sink")
    if sensitive and external and _reachable(graph, sensitive, external):
        return [Finding(
            constraint="C3_SENSITIVE_TO_EXTERNAL_SEQUENCE",
            severity=Severity.CRITICAL,
            message="Sensitive data reaches an external sink through a tool-call sequence.",
            evidence=_path_evidence(graph, sensitive, external),
        )]
    return []


# ---------------------------------------------------------------------------
# C4: Version Drift After Approval
# ---------------------------------------------------------------------------


def _c4_post_approval_drift(graph: EvidenceGraph) -> List[Finding]:
    """C4: approved skill version shows high-risk post-approval drift."""
    findings: List[Finding] = []
    seen_subjects: Set[str] = set()
    for drift in graph.find(predicate="post_approval_drift", object="high"):
        findings.append(Finding(
            constraint="C4_POST_APPROVAL_DRIFT",
            severity=Severity.HIGH,
            message="A previously approved skill version shows high-risk post-approval behavior drift.",
            evidence=[drift],
        ))
        seen_subjects.add(drift.subject)
    for change in graph.find(predicate="high_risk_version_change"):
        if change.subject not in seen_subjects:
            findings.append(Finding(
                constraint="C4_POST_APPROVAL_DRIFT",
                severity=Severity.HIGH,
                message="A skill version update introduces high-risk capabilities after approval.",
                evidence=[change],
            ))
    return findings


# ---------------------------------------------------------------------------
# C5: Approval Integrity
# ---------------------------------------------------------------------------


def _c5_tainted_approval_text(graph: EvidenceGraph) -> List[Finding]:
    """C5: approval dialog text is derived from untrusted context."""
    findings: List[Finding] = []
    for approval in graph.find(predicate="approval_text_lineage", object="untrusted_context_only"):
        findings.append(Finding(
            constraint="C5_TAINTED_APPROVAL_TEXT",
            severity=Severity.HIGH,
            message="Approval dialog is derived only from untrusted/model context instead of execution-layer facts.",
            evidence=[approval],
        ))
    return findings


# ---------------------------------------------------------------------------
# C6: Persistence Boundary
# ---------------------------------------------------------------------------


def _c6_untrusted_persistence_write(graph: EvidenceGraph) -> List[Finding]:
    """C6: untrusted/external source reaches a persistent store write."""
    untrusted = _untrusted_subjects(graph)
    persistent = graph.subjects_with("writes_persistent_store")
    if untrusted and persistent and _reachable(graph, untrusted, persistent):
        return [Finding(
            constraint="C6_UNTRUSTED_PERSISTENCE_WRITE",
            severity=Severity.HIGH,
            message="Untrusted source reaches a persistent store such as memory/config/hooks/policy store.",
            evidence=_path_evidence(graph, untrusted, persistent),
        )]
    return []


# ---------------------------------------------------------------------------
# C7: Least-Privilege Scope Alignment
# ---------------------------------------------------------------------------


def _c7_least_privilege_scope(graph: EvidenceGraph) -> List[Finding]:
    """C7: task context suggests read-only need but skill requests elevated scope."""
    findings: List[Finding] = []
    read_only_tasks: Set[str] = {
        e.subject for e in graph.evidence
        if e.predicate == "task_context"
        and e.object in {"read", "summarize", "search", "query", "list"}
    }
    read_only_tasks |= graph.subjects_with("declares_capability", "read_only_or_low_risk")
    read_only_tasks |= graph.subjects_with("annotation_claims", "read_only")

    for subject in read_only_tasks:
        scope_evidence = [
            e for e in graph.find(subject=subject, predicate="requires_scope")
            if e.object in HIGH_RISK_SCOPES
        ]
        scope_evidence.extend(graph.find(subject=subject, predicate="requires_high_risk_scope"))
        if scope_evidence:
            task_ctx = (
                graph.find(subject=subject, predicate="task_context")
                + graph.find(subject=subject, predicate="declares_capability")
                + graph.find(subject=subject, predicate="annotation_claims")
            )
            findings.append(Finding(
                constraint="C7_LEAST_PRIVILEGE_SCOPE",
                severity=Severity.MEDIUM,
                message="Task context indicates read-only need but skill requests elevated scope.",
                evidence=task_ctx + scope_evidence,
            ))
    return findings
