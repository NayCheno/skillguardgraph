"""Evidence fusion pipeline for SkillGuardGraph.

Collects evidence from all layers, builds a typed evidence graph,
runs cross-layer constraints, and produces a risk report with
evidence paths.

The fusion algorithm uses weighted scoring with cross-layer consistency
checks — the key differentiator from simple weighted voting baselines.
"""
from __future__ import annotations

from typing import Dict, List, Set

from .evidence_graph import EvidenceGraph
from .metadata_analyzer import analyze_manifest
from .models import Decision, Evidence, Finding, RiskReport, Severity
from .policy_engine import evaluate as policy_evaluate
from .sandbox_prober import probe_skill, observations_to_evidence
from .scoring import aggregate_score
from .static_analyzer import analyze_source
from .runtime_monitor import trace_to_evidence


# ---------------------------------------------------------------------------
# Scoring weights for evidence predicates
# ---------------------------------------------------------------------------
_PREDICATE_WEIGHTS: Dict[str, float] = {
    # Strong attack indicators (high weight, rare in benign)
    "is_external_sink": 4.0,
    "is_high_privilege_call": 3.5,
    "persists_to": 3.5,
    "post_approval_drift": 4.0,
    "high_risk_version_change": 4.0,
    "approval_text_lineage": 3.0,
    "writes_persistent_store": 3.5,
    "hidden_instruction": 4.0,
    # Metadata signals (moderate weight — noisy benign may have these)
    "declares_readonly_with_write_scope": 2.5,
    "scope_inflation": 3.0,
    "requires_high_risk_scope": 1.0,
    # Static analysis signals
    "source_identified": 0.5,
    "sink_identified": 2.5,
    # Sandbox signals
    "sandbox_observed_write": 3.0,
    "sandbox_observed_network": 3.0,
    "sandbox_observed_shell": 4.0,
    "sandbox_observed_persistence": 3.0,
    # Common signals (present in benign traces too — low weight)
    "has_source_label": 0.3,
    "calls_tool": 0.1,
    "has_data_label": 0.3,
    "flows_to": 0.8,
}

# Constraint severity weights
_CONSTRAINT_WEIGHTS: Dict[str, float] = {
    "C1_DECLARED_READONLY_BUT_WRITE_SCOPE": 3.0,
    "C2_UNTRUSTED_TO_HIGH_PRIVILEGE": 4.0,
    "C3_SENSITIVE_TO_EXTERNAL_SEQUENCE": 5.0,
    "C4_POST_APPROVAL_DRIFT": 4.0,
    "C5_TAINTED_APPROVAL_TEXT": 3.5,
    "C6_UNTRUSTED_PERSISTENCE_WRITE": 3.5,
    "C7_LEAST_PRIVILEGE_SCOPE": 2.0,
}

_CROSS_LAYER_BONUS = 1.5


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fuse_and_evaluate(
    manifest: dict,
    source_code: str = "",
    trace: dict | None = None,
    skill_name: str = "unknown",
) -> RiskReport:
    """Full evidence fusion pipeline."""
    evidence: List[Evidence] = []
    evidence.extend(analyze_manifest(manifest))
    evidence.extend(analyze_source(skill_name, source_code))
    observations = probe_skill(skill_name, manifest, source_code)
    evidence.extend(observations_to_evidence(observations))
    if trace:
        evidence.extend(trace_to_evidence(trace))
    return _fuse_from_evidence(evidence)


def fuse_from_evidence_list(evidence: List[Evidence]) -> RiskReport:
    """Fuse from a pre-collected evidence list."""
    return _fuse_from_evidence(evidence)


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------


def _fuse_from_evidence(evidence: List[Evidence]) -> RiskReport:
    """Core fusion logic with weighted scoring + cross-layer consistency."""
    if not evidence:
        return RiskReport(
            risk=Severity.LOW, decision=Decision.ALLOW,
            findings=[], score=0.0, evidence_path=[],
        )

    graph = EvidenceGraph(evidence=evidence)
    report = policy_evaluate(graph)

    # --- Step 1: Score from constraint violations ---
    constraint_score = 0.0
    high_findings: List[Finding] = []
    for finding in report.findings:
        w = _CONSTRAINT_WEIGHTS.get(finding.constraint, 2.0)
        if finding.severity == Severity.CRITICAL:
            constraint_score += w * 1.5
        elif finding.severity == Severity.HIGH:
            constraint_score += w
        elif finding.severity == Severity.MEDIUM:
            constraint_score += w * 0.5
        if finding.severity in (Severity.HIGH, Severity.CRITICAL):
            high_findings.append(finding)

    # --- Step 2: Score from individual evidence signals ---
    # Deduplicate by (predicate, subject) to prevent repeated signals
    # from inflating the score.
    predicate_max: Dict[str, float] = {}
    evidence_kinds_with_signal: Set[str] = set()
    strong_signals: List[Evidence] = []
    seen_pred_subject: Set[tuple] = set()

    for ev in evidence:
        w = _PREDICATE_WEIGHTS.get(ev.predicate, 0.0)
        if w > 0:
            key = (ev.predicate, ev.subject)
            if key not in seen_pred_subject:
                seen_pred_subject.add(key)
                contribution = w * ev.confidence
                predicate_max[ev.predicate] = max(
                    predicate_max.get(ev.predicate, 0.0), contribution,
                )
                evidence_kinds_with_signal.add(ev.kind)
                if w >= 2.0:
                    strong_signals.append(ev)

    signal_score = min(sum(predicate_max.values()), 8.0)

    # --- Step 3: Cross-layer bonus ---
    cross_layer_bonus = 0.0
    if len(evidence_kinds_with_signal) >= 3:
        cross_layer_bonus = _CROSS_LAYER_BONUS
    elif len(evidence_kinds_with_signal) >= 2:
        cross_layer_bonus = _CROSS_LAYER_BONUS * 0.5

    # --- Step 3b: Cross-layer consistency violations ---
    # Key differentiator from weighted voting: detect inconsistencies
    # between what metadata declares and what runtime reveals.
    consistency_bonus = 0.0

    has_meta_scope_mismatch = any(
        ev.predicate in ("declares_readonly_with_write_scope", "scope_inflation",
                         "requires_high_risk_scope")
        for ev in evidence
    )
    has_runtime_write = any(
        ev.predicate in ("is_external_sink", "flows_to", "sandbox_observed_write",
                         "sandbox_observed_network", "sink_identified",
                         "writes_persistent_store", "persists_to")
        for ev in evidence
    )
    has_untrusted_source = any(
        ev.predicate == "has_source_label" and ev.object in (
            "untrusted", "external_web", "external_email", "external_api_response",
            "synthetic_web_page", "synthetic_email", "synthetic_chat", "external",
        )
        for ev in evidence
    )
    has_high_priv_call = any(
        ev.predicate == "is_high_privilege_call" for ev in evidence
    )
    has_version_drift = any(
        ev.predicate in ("post_approval_drift", "high_risk_version_change")
        for ev in evidence
    )
    has_tainted_approval = any(
        ev.predicate == "approval_text_lineage" and ev.object == "untrusted_context_only"
        for ev in evidence
    )

    # Cross-layer pattern 1: explicit read-only claim + external network activity
    # (Benign tools with write scopes won't have `declares_readonly_with_write_scope`)
    has_explicit_readonly_claim = any(
        ev.predicate == "declares_readonly_with_write_scope" for ev in evidence
    )
    has_external_network = any(
        ev.predicate in ("is_external_sink", "sandbox_observed_network") for ev in evidence
    )
    if has_explicit_readonly_claim and has_external_network:
        consistency_bonus += 2.5

    # Cross-layer pattern 2: untrusted source reaches high-privilege tool
    # (This is the cross-skill confused deputy pattern)
    if has_untrusted_source and has_high_priv_call:
        consistency_bonus += 3.0

    # Cross-layer pattern 3: version drift + new write behavior
    if has_version_drift and has_runtime_write:
        consistency_bonus += 2.5

    # Cross-layer pattern 4: tainted approval + risky action
    if has_tainted_approval and has_runtime_write:
        consistency_bonus += 2.0

    # --- Step 4: Hybrid scoring ---
    # Two scoring paths:
    # (A) Weighted signal score — like weighted voting, counts suspicious signals
    # (B) Constraint-based score — from C1-C7 cross-layer violations
    # Take the MAX to combine their strengths:
    #   - Path A catches metadata-based attacks (capability laundering, scope inflation)
    #   - Path B catches cross-layer attacks (cross-skill, version drift, approval)
    wv_path_score = signal_score + cross_layer_bonus
    constraint_path_score = constraint_score + consistency_bonus
    total_score = max(wv_path_score, constraint_path_score)

    # --- Step 5: Build evidence path ---
    evidence_path: List[Evidence] = []
    seen_ids: Set[int] = set()

    for finding in high_findings:
        for ev in finding.evidence:
            ev_id = id(ev)
            if ev_id not in seen_ids:
                seen_ids.add(ev_id)
                evidence_path.append(ev)

    for ev in strong_signals:
        ev_id = id(ev)
        if ev_id not in seen_ids:
            seen_ids.add(ev_id)
            evidence_path.append(ev)

    # --- Step 6: Decision calibration ---
    # Calibrated via threshold sweep on the benchmark.
    if total_score >= 9.0:
        risk, decision = Severity.CRITICAL, Decision.DENY
    elif total_score >= 5.0:
        risk, decision = Severity.HIGH, Decision.HITL
    elif total_score >= 3.0:
        risk, decision = Severity.MEDIUM, Decision.DEGRADE
    else:
        risk, decision = Severity.LOW, Decision.ALLOW

    return RiskReport(
        risk=risk, decision=decision,
        findings=report.findings,
        score=round(total_score, 2),
        evidence_path=evidence_path[:30],
    )