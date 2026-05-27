"""Constraint library for the SkillGuardGraph evidence graph.

Each constraint function takes an EvidenceGraph and returns a list of Findings.
Constraints are evaluated by the policy engine and can also be tested independently.

Constraints:
    C1: declared-read-only-but-write-scope (capability consistency)
    C2: untrusted-to-high-privilege flow (source-aware information flow)
    C3: sensitive-to-external sequence (cross-tool exfiltration)
    C4: post-approval drift (version drift)
    C5: tainted approval text (approval integrity)
    C6: untrusted persistence write (persistence boundary)
    C7: least-privilege scope alignment
"""
from __future__ import annotations

from typing import List, Set

from .evidence_graph import EvidenceGraph
from .models import Evidence, Finding, Severity

HIGH_RISK_SCOPES = {"write", "delete", "export", "send", "admin", "modify"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reachable(graph: EvidenceGraph, starts: Set[str], targets: Set[str], max_depth: int = 6) -> bool:
    """BFS reachability through flows_to edges in evidence."""
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
    """Collect evidence along a path from starts to targets."""
    out: List[Evidence] = []
    for start in starts:
        out.extend(graph.find(subject=start, predicate="has_source_label"))
        out.extend(graph.find(subject=start, predicate="has_data_label"))
        out.extend(graph.find(subject=start, predicate="flows_to"))
    for target in targets:
        out.extend(graph.find(subject=target))
    return out[:20]


# ---------------------------------------------------------------------------
# C1: Capability Consistency
# ---------------------------------------------------------------------------


def c1_declared_readonly_but_write_scope(graph: EvidenceGraph) -> List[Finding]:
    """C1: declared capability conflicts with granted permission scope.

    Trigger: manifest declares read-only or low-risk, but scopes include
    write/delete/export/send/admin.
    Risk level: HIGH.
    Policy: HITL or DENY.
    """
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
            supporting = (
                graph.find(subject=subject, predicate="declares_capability")
                + graph.find(subject=subject, predicate="annotation_claims")
                + scope_evidence
            )
            findings.append(
                Finding(
                    constraint="C1_DECLARED_READONLY_BUT_WRITE_SCOPE",
                    severity=Severity.HIGH,
                    message="Skill declares read-only or low-risk behavior but requests write/export/admin-like scope.",
                    evidence=supporting,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# C2: Source-Aware Information Flow
# ---------------------------------------------------------------------------


def c2_untrusted_to_high_privilege(graph: EvidenceGraph) -> List[Finding]:
    """C2: untrusted source reaches a high-privilege tool call.

    Trigger: BFS through flows_to edges from untrusted source nodes to
    high-privilege call nodes.
    Risk level: HIGH.
    Policy: HITL.
    """
    untrusted = graph.subjects_with("has_source_label", "untrusted")
    high_priv = graph.subjects_with("is_high_privilege_call")
    if untrusted and high_priv and _reachable(graph, untrusted, high_priv):
        return [
            Finding(
                constraint="C2_UNTRUSTED_TO_HIGH_PRIVILEGE",
                severity=Severity.HIGH,
                message="Untrusted source reaches a high-privilege tool call through runtime provenance.",
                evidence=_path_evidence(graph, untrusted, high_priv),
            )
        ]
    return []


# ---------------------------------------------------------------------------
# C3: Cross-Tool Exfiltration
# ---------------------------------------------------------------------------


def c3_sensitive_to_external_sequence(graph: EvidenceGraph) -> List[Finding]:
    """C3: sensitive data reaches an external sink through a tool-call sequence.

    Trigger: BFS from confidential/secret/pii/credential data nodes to
    external sink nodes.
    Risk level: CRITICAL.
    Policy: DENY.
    """
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
                message="Sensitive data reaches an external sink through a tool-call sequence.",
                evidence=_path_evidence(graph, sensitive, external),
            )
        ]
    return []


# ---------------------------------------------------------------------------
# C4: Version Drift
# ---------------------------------------------------------------------------


def c4_post_approval_drift(graph: EvidenceGraph) -> List[Finding]:
    """C4: approved skill version shows high-risk post-approval drift.

    Trigger: evidence of post_approval_drift=high or high_risk_version_change.
    Risk level: HIGH.
    Policy: ROLLBACK or QUARANTINE.
    """
    findings: List[Finding] = []
    seen_subjects: Set[str] = set()
    for drift in graph.find(predicate="post_approval_drift", object="high"):
        findings.append(
            Finding(
                constraint="C4_POST_APPROVAL_DRIFT",
                severity=Severity.HIGH,
                message="A previously approved skill version shows high-risk post-approval behavior drift.",
                evidence=[drift],
            )
        )
        seen_subjects.add(drift.subject)
    for change in graph.find(predicate="high_risk_version_change"):
        if change.subject not in seen_subjects:
            findings.append(
                Finding(
                    constraint="C4_POST_APPROVAL_DRIFT",
                    severity=Severity.HIGH,
                    message="A skill version update introduces high-risk capabilities after approval.",
                    evidence=[change],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# C5: Approval Integrity
# ---------------------------------------------------------------------------


def c5_tainted_approval_text(graph: EvidenceGraph) -> List[Finding]:
    """C5: approval dialog text is derived from untrusted context.

    Trigger: approval_text_lineage=untrusted_context_only.
    Risk level: HIGH.
    Policy: HITL with execution-layer facts.
    """
    findings: List[Finding] = []
    for approval in graph.find(predicate="approval_text_lineage", object="untrusted_context_only"):
        findings.append(
            Finding(
                constraint="C5_TAINTED_APPROVAL_TEXT",
                severity=Severity.HIGH,
                message="Approval dialog is derived only from untrusted/model context instead of execution-layer facts.",
                evidence=[approval],
            )
        )
    return findings


# ---------------------------------------------------------------------------
# C6: Persistence Boundary
# ---------------------------------------------------------------------------


def c6_untrusted_persistence_write(graph: EvidenceGraph) -> List[Finding]:
    """C6: untrusted source reaches a persistent store write.

    Trigger: BFS from untrusted sources to persistence write targets.
    Risk level: HIGH.
    Policy: DENY or QUARANTINE.
    """
    untrusted = graph.subjects_with("has_source_label", "untrusted")
    persistent = graph.subjects_with("writes_persistent_store")
    if untrusted and persistent and _reachable(graph, untrusted, persistent):
        return [
            Finding(
                constraint="C6_UNTRUSTED_PERSISTENCE_WRITE",
                severity=Severity.HIGH,
                message="Untrusted source reaches a persistent store such as memory/config/hooks/policy store.",
                evidence=_path_evidence(graph, untrusted, persistent),
            )
        ]
    return []


# ---------------------------------------------------------------------------
# C7: Least-Privilege Scope Alignment
# ---------------------------------------------------------------------------


def c7_least_privilege_scope(graph: EvidenceGraph) -> List[Finding]:
    """C7: task context suggests read-only need but skill requests elevated scope.

    Trigger: task_context/read_only declaration combined with write/delete/export scope.
    Risk level: MEDIUM.
    Policy: DEGRADE.
    """
    findings: List[Finding] = []
    read_only_tasks: Set[str] = {
        e.subject
        for e in graph.evidence
        if e.predicate == "task_context"
        and e.object in {"read", "summarize", "search", "query", "list"}
    }
    read_only_tasks |= graph.subjects_with("declares_capability", "read_only_or_low_risk")
    read_only_tasks |= graph.subjects_with("annotation_claims", "read_only")

    for subject in read_only_tasks:
        scope_evidence = [
            e
            for e in graph.find(subject=subject, predicate="requires_scope")
            if e.object in HIGH_RISK_SCOPES
        ]
        scope_evidence.extend(
            graph.find(subject=subject, predicate="requires_high_risk_scope")
        )
        if scope_evidence:
            task_ctx = graph.find(subject=subject, predicate="task_context")
            task_ctx += graph.find(subject=subject, predicate="declares_capability")
            task_ctx += graph.find(subject=subject, predicate="annotation_claims")
            findings.append(
                Finding(
                    constraint="C7_LEAST_PRIVILEGE_SCOPE",
                    severity=Severity.MEDIUM,
                    message="Task context indicates read-only need but skill requests elevated scope.",
                    evidence=task_ctx + scope_evidence,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CONSTRAINTS = {
    "C1": c1_declared_readonly_but_write_scope,
    "C2": c2_untrusted_to_high_privilege,
    "C3": c3_sensitive_to_external_sequence,
    "C4": c4_post_approval_drift,
    "C5": c5_tainted_approval_text,
    "C6": c6_untrusted_persistence_write,
    "C7": c7_least_privilege_scope,
}


def evaluate_all(graph: EvidenceGraph) -> List[Finding]:
    """Evaluate all constraints against the evidence graph."""
    findings: List[Finding] = []
    for constraint_fn in CONSTRAINTS.values():
        findings.extend(constraint_fn(graph))
    return findings
