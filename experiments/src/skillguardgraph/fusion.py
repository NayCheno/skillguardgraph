"""Evidence fusion pipeline for SkillGuardGraph.

Collects evidence from all available cross-layer sources, builds an evidence
graph, runs policy evaluation, and returns a risk report with evidence paths.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .evidence_graph import EvidenceGraph
from .metadata_analyzer import analyze_manifest
from .models import Decision, Evidence, Finding, RiskReport, Severity
from .policy_engine import evaluate as policy_evaluate
from .sandbox_prober import observations_to_evidence
from .scoring import aggregate_score
from .static_analyzer import analyze_source
from .runtime_monitor import trace_to_evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fuse_and_evaluate(
    manifest: Dict[str, Any] | None = None,
    source_code: str | None = None,
    runtime_trace: Dict[str, Any] | None = None,
    sandbox_observations: List[Any] | None = None,
) -> RiskReport:
    """Full evidence fusion pipeline.

    Collects evidence from all available sources, builds an evidence graph,
    runs policy evaluation, and returns a risk report with evidence paths.
    """
    evidence: List[Evidence] = []

    # 1. Metadata evidence from manifest
    if manifest is not None:
        evidence.extend(analyze_manifest(manifest))

    # 2. Static analysis evidence from source code
    if source_code is not None:
        skill_name = "unknown_skill"
        if manifest is not None:
            skill_name = str(manifest.get("name") or manifest.get("id") or "unknown_skill")
        evidence.extend(analyze_source(skill_name, source_code))

    # 3. Sandbox observation evidence
    if sandbox_observations is not None:
        evidence.extend(observations_to_evidence(sandbox_observations))

    # 4. Runtime trace evidence
    if runtime_trace is not None:
        evidence.extend(trace_to_evidence(runtime_trace))

    return _fuse_from_evidence(evidence)


def fuse_from_evidence_list(evidence: List[Evidence]) -> RiskReport:
    """Fuse from a pre-collected evidence list."""
    return _fuse_from_evidence(evidence)


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


def _fuse_from_evidence(evidence: List[Evidence]) -> RiskReport:
    """Core fusion logic shared by both entry points.

    1. Build an EvidenceGraph from the combined evidence.
    2. Run policy evaluation to get findings.
    3. If policy finds cross-layer violations, use those.
    4. Otherwise, apply multi-layer agreement: if suspicious signals
       appear across 2+ independent evidence kinds, elevate to HIGH.
    5. Return a RiskReport with evidence paths.
    """
    if not evidence:
        return RiskReport(
            risk=Severity.LOW,
            decision=Decision.ALLOW,
            findings=[],
            score=0.0,
            evidence_path=[],
        )

    # Build graph
    graph = EvidenceGraph(evidence=evidence)

    # Policy evaluation (cross-layer constraints)
    report = policy_evaluate(graph)

    # If policy already found HIGH/CRITICAL findings, keep that
    if report.risk in (Severity.HIGH, Severity.CRITICAL):
        evidence_path: List[Evidence] = []
        seen_ids: set[int] = set()
        for finding in report.findings:
            if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                for ev in finding.evidence:
                    ev_id = id(ev)
                    if ev_id not in seen_ids:
                        seen_ids.add(ev_id)
                        evidence_path.append(ev)
        report.evidence_path = evidence_path
        return report

    # Multi-layer agreement fallback: count suspicious signals per kind
    _SUSPICIOUS = {
        "declares_readonly_with_write_scope", "scope_inflation",
        "hidden_instruction", "has_source_label", "requires_high_risk_scope",
        "source_identified", "sink_identified", "is_external_sink",
        "is_credential_access", "is_pii_access", "sandbox_observed_write",
        "sandbox_observed_network", "sandbox_observed_shell",
        "sandbox_observed_persistence", "flows_to", "persists_to",
        "high_privilege_tool", "external_sink",
    }
    suspicious_kinds: set[str] = set()
    suspicious_evidence: List[Evidence] = []
    for ev in evidence:
        if ev.predicate in _SUSPICIOUS:
            suspicious_kinds.add(ev.kind)
            suspicious_evidence.append(ev)

    if len(suspicious_kinds) >= 2 and suspicious_evidence:
        # Multi-layer agreement: elevate to HIGH
        return RiskReport(
            risk=Severity.HIGH,
            decision=Decision.HITL,
            findings=report.findings,
            score=max(report.score, 6.0),
            evidence_path=suspicious_evidence[:20],
        )

    # Single-layer suspicious: MEDIUM
    if suspicious_evidence:
        return RiskReport(
            risk=Severity.MEDIUM,
            decision=Decision.DEGRADE,
            findings=report.findings,
            score=max(report.score, 3.0),
            evidence_path=suspicious_evidence[:20],
        )

    report.evidence_path = []
    return report
