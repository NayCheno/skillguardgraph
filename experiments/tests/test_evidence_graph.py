"""Tests for the SkillGuardGraph evidence graph and constraint library.

Covers:
- EvidenceGraph construction and querying
- All 7 constraints (C1-C7) with positive and negative cases
- Evidence path serialization
- Graceful degradation with missing data
"""
from __future__ import annotations

import json

import pytest

from skillguardgraph.constraints import (
    c1_declared_readonly_but_write_scope,
    c2_untrusted_to_high_privilege,
    c3_sensitive_to_external_sequence,
    c4_post_approval_drift,
    c5_tainted_approval_text,
    c6_untrusted_persistence_write,
    c7_least_privilege_scope,
    evaluate_all,
)
from skillguardgraph.evidence_graph import EvidenceGraph
from skillguardgraph.models import Evidence, Finding, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ev(kind="metadata", subject="skill1", predicate="declares_capability",
        object_="read_only_or_low_risk", confidence=0.9, attrs=None):
    return Evidence(
        kind=kind, subject=subject, predicate=predicate,
        object=object_, confidence=confidence, attrs=attrs or {},
    )


# ---------------------------------------------------------------------------
# EvidenceGraph construction
# ---------------------------------------------------------------------------


class TestEvidenceGraph:
    def test_empty_graph(self):
        graph = EvidenceGraph(evidence=[])
        assert len(graph.evidence) == 0

    def test_graph_from_evidence(self):
        evidence = [
            _ev(predicate="declares_capability", object_="read_only_or_low_risk"),
            _ev(predicate="requires_scope", object_="write"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        assert len(graph.evidence) == 2

    def test_find_by_subject(self):
        evidence = [
            _ev(subject="skill1", predicate="declares_capability"),
            _ev(subject="skill2", predicate="declares_capability"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        results = graph.find(subject="skill1")
        assert len(results) == 1
        assert results[0].subject == "skill1"

    def test_find_by_predicate(self):
        evidence = [
            _ev(predicate="declares_capability"),
            _ev(predicate="requires_scope"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        results = graph.find(predicate="requires_scope")
        assert len(results) == 1

    def test_subjects_with(self):
        evidence = [
            _ev(subject="call1", predicate="has_source_label", object_="untrusted"),
            _ev(subject="call2", predicate="has_source_label", object_="internal"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        untrusted = graph.subjects_with("has_source_label", "untrusted")
        assert "call1" in untrusted
        assert "call2" not in untrusted

    def test_to_dict_serializable(self):
        evidence = [_ev()]
        graph = EvidenceGraph(evidence=evidence)
        d = graph.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert isinstance(json_str, str)

    def test_graceful_degradation_empty_manifest(self):
        """Graph construction with empty evidence should not crash."""
        graph = EvidenceGraph(evidence=[])
        assert len(graph.evidence) == 0
        assert graph.find(predicate="anything") == []


# ---------------------------------------------------------------------------
# C1: Capability Consistency
# ---------------------------------------------------------------------------


class TestC1CapabilityConsistency:
    def test_readonly_with_write_scope_triggers(self):
        evidence = [
            _ev(predicate="declares_capability", object_="read_only_or_low_risk"),
            _ev(kind="permission", predicate="requires_scope", object_="write"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c1_declared_readonly_but_write_scope(graph)
        assert len(findings) == 1
        assert findings[0].constraint == "C1_DECLARED_READONLY_BUT_WRITE_SCOPE"
        assert findings[0].severity == Severity.HIGH

    def test_readonly_with_read_scope_no_trigger(self):
        evidence = [
            _ev(predicate="declares_capability", object_="read_only_or_low_risk"),
            _ev(kind="permission", predicate="requires_scope", object_="read"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c1_declared_readonly_but_write_scope(graph)
        assert len(findings) == 0

    def test_annotation_readonly_with_export_scope(self):
        evidence = [
            _ev(predicate="annotation_claims", object_="read_only"),
            _ev(kind="permission", predicate="requires_scope", object_="export"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c1_declared_readonly_but_write_scope(graph)
        assert len(findings) == 1

    def test_no_readonly_declaration_no_trigger(self):
        evidence = [
            _ev(predicate="declares_capability", object_="data_processing"),
            _ev(kind="permission", predicate="requires_scope", object_="write"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c1_declared_readonly_but_write_scope(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# C2: Source-Aware Information Flow
# ---------------------------------------------------------------------------


class TestC2SourceAwareFlow:
    def test_untrusted_to_high_privilege_triggers(self):
        evidence = [
            _ev(subject="src", predicate="has_source_label", object_="untrusted"),
            _ev(subject="src", predicate="flows_to", object_="call1"),
            _ev(subject="call1", predicate="is_high_privilege_call", object_="true"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c2_untrusted_to_high_privilege(graph)
        assert len(findings) == 1
        assert findings[0].constraint == "C2_UNTRUSTED_TO_HIGH_PRIVILEGE"

    def test_no_untrusted_source_no_trigger(self):
        evidence = [
            _ev(subject="src", predicate="has_source_label", object_="internal"),
            _ev(subject="src", predicate="flows_to", object_="call1"),
            _ev(subject="call1", predicate="is_high_privilege_call", object_="true"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c2_untrusted_to_high_privilege(graph)
        assert len(findings) == 0

    def test_untrusted_no_path_no_trigger(self):
        evidence = [
            _ev(subject="src", predicate="has_source_label", object_="untrusted"),
            _ev(subject="call1", predicate="is_high_privilege_call", object_="true"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c2_untrusted_to_high_privilege(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# C3: Cross-Tool Exfiltration
# ---------------------------------------------------------------------------


class TestC3CrossToolExfiltration:
    def test_sensitive_to_external_triggers(self):
        evidence = [
            _ev(subject="data1", predicate="has_data_label", object_="confidential"),
            _ev(subject="data1", predicate="flows_to", object_="sink1"),
            _ev(subject="sink1", predicate="is_external_sink", object_="true"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c3_sensitive_to_external_sequence(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_public_data_to_external_no_trigger(self):
        evidence = [
            _ev(subject="data1", predicate="has_data_label", object_="public"),
            _ev(subject="data1", predicate="flows_to", object_="sink1"),
            _ev(subject="sink1", predicate="is_external_sink", object_="true"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c3_sensitive_to_external_sequence(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# C4: Version Drift
# ---------------------------------------------------------------------------


class TestC4VersionDrift:
    def test_drift_triggers(self):
        evidence = [
            _ev(subject="skill1", predicate="post_approval_drift", object_="high"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c4_post_approval_drift(graph)
        assert len(findings) == 1
        assert findings[0].constraint == "C4_POST_APPROVAL_DRIFT"

    def test_no_drift_no_trigger(self):
        evidence = [
            _ev(subject="skill1", predicate="post_approval_drift", object_="low"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c4_post_approval_drift(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# C5: Approval Integrity
# ---------------------------------------------------------------------------


class TestC5ApprovalIntegrity:
    def test_tainted_approval_triggers(self):
        evidence = [
            _ev(predicate="approval_text_lineage", object_="untrusted_context_only"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c5_tainted_approval_text(graph)
        assert len(findings) == 1

    def test_clean_approval_no_trigger(self):
        evidence = [
            _ev(predicate="approval_text_lineage", object_="execution_layer_facts"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c5_tainted_approval_text(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# C6: Persistence Boundary
# ---------------------------------------------------------------------------


class TestC6PersistenceBoundary:
    def test_untrusted_to_persistence_triggers(self):
        evidence = [
            _ev(subject="src", predicate="has_source_label", object_="untrusted"),
            _ev(subject="src", predicate="flows_to", object_="store1"),
            _ev(subject="store1", predicate="writes_persistent_store", object_="true"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c6_untrusted_persistence_write(graph)
        assert len(findings) == 1

    def test_trusted_to_persistence_no_trigger(self):
        evidence = [
            _ev(subject="src", predicate="has_source_label", object_="internal"),
            _ev(subject="src", predicate="flows_to", object_="store1"),
            _ev(subject="store1", predicate="writes_persistent_store", object_="true"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c6_untrusted_persistence_write(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# C7: Least-Privilege Scope Alignment
# ---------------------------------------------------------------------------


class TestC7LeastPrivilege:
    def test_readonly_task_with_write_scope_triggers(self):
        evidence = [
            _ev(subject="skill1", predicate="task_context", object_="read"),
            _ev(kind="permission", subject="skill1", predicate="requires_scope", object_="write"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c7_least_privilege_scope(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_readonly_task_with_read_scope_no_trigger(self):
        evidence = [
            _ev(subject="skill1", predicate="task_context", object_="read"),
            _ev(kind="permission", subject="skill1", predicate="requires_scope", object_="read"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = c7_least_privilege_scope(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Evaluate all constraints
# ---------------------------------------------------------------------------


class TestEvaluateAll:
    def test_evaluate_all_returns_multiple_findings(self):
        evidence = [
            # C1 trigger
            _ev(subject="s1", predicate="declares_capability", object_="read_only_or_low_risk"),
            _ev(kind="perm", subject="s1", predicate="requires_scope", object_="write"),
            # C7 trigger
            _ev(subject="s1", predicate="task_context", object_="read"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = evaluate_all(graph)
        constraints_hit = {f.constraint for f in findings}
        assert "C1_DECLARED_READONLY_BUT_WRITE_SCOPE" in constraints_hit
        assert "C7_LEAST_PRIVILEGE_SCOPE" in constraints_hit

    def test_evaluate_all_clean_skill(self):
        evidence = [
            _ev(predicate="declares_capability", object_="data_processing"),
            _ev(kind="perm", predicate="requires_scope", object_="read"),
        ]
        graph = EvidenceGraph(evidence=evidence)
        findings = evaluate_all(graph)
        # No high-risk constraints should trigger for a clean skill
        high_findings = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert len(high_findings) == 0
