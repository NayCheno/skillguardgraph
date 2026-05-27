from skillguardgraph.evidence_graph import EvidenceGraph
from skillguardgraph.metadata_analyzer import analyze_manifest
from skillguardgraph.models import Decision, Evidence, Severity
from skillguardgraph.policy_engine import evaluate
from skillguardgraph.runtime_monitor import trace_to_evidence


def test_declared_readonly_but_write_scope():
    manifest = {
        "name": "doc_helper",
        "description": "Read-only summarizer",
        "scopes": ["read", "export"],
        "annotations": {"readOnlyHint": True},
    }
    graph = EvidenceGraph(analyze_manifest(manifest))
    report = evaluate(graph)
    assert report.risk == Severity.HIGH
    assert any(f.constraint == "C1_DECLARED_READONLY_BUT_WRITE_SCOPE" for f in report.findings)


def test_sensitive_to_external_sequence():
    trace = {
        "trace_id": "t",
        "events": [
            {"id": "d", "type": "data", "sensitivity": "confidential"},
            {"id": "s", "type": "sink", "sink": "sinkhole", "external": True},
        ],
        "flows": [{"from": "d", "to": "s"}],
    }
    graph = EvidenceGraph(trace_to_evidence(trace))
    report = evaluate(graph)
    assert report.risk == Severity.CRITICAL
    assert report.decision == Decision.DENY
    assert any(f.constraint == "C3_SENSITIVE_TO_EXTERNAL_SEQUENCE" for f in report.findings)


def test_post_approval_drift():
    graph = EvidenceGraph(
        [
            Evidence(
                kind="version",
                subject="skill:v2",
                predicate="post_approval_drift",
                object="high",
                confidence=0.9,
            )
        ]
    )
    report = evaluate(graph)
    assert any(f.constraint == "C4_POST_APPROVAL_DRIFT" for f in report.findings)


def test_untrusted_persistence_write():
    trace = {
        "trace_id": "p",
        "events": [
            {"id": "u", "type": "source", "label": "untrusted"},
            {"id": "m", "type": "persistence_write", "store": "agent_memory"},
        ],
        "flows": [{"from": "u", "to": "m"}],
    }
    graph = EvidenceGraph(trace_to_evidence(trace))
    report = evaluate(graph)
    assert any(f.constraint == "C6_UNTRUSTED_PERSISTENCE_WRITE" for f in report.findings)
