"""Typed data models for the SkillGuardGraph cross-layer evidence fusion system.

Node types, edge types, evidence items, findings, and risk reports.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "allow"
    DEGRADE = "degrade"
    HITL = "hitl"
    SANDBOX_ONLY = "sandbox_only"
    DENY = "deny"
    QUARANTINE = "quarantine"
    ROLLBACK = "rollback"


class NodeType(str, Enum):
    """Typed nodes in the evidence graph."""
    SKILL = "skill"
    VERSION = "version"
    METADATA = "metadata"
    CODE_SLICE = "code_slice"
    RUNTIME_EVENT = "runtime_event"
    DATA_OBJECT = "data_object"
    TRUST_LABEL = "trust_label"
    SENSITIVITY_LABEL = "sensitivity_label"
    POLICY_DECISION = "policy_decision"


class EdgeType(str, Enum):
    """Typed edges in the evidence graph."""
    DECLARES = "declares"
    IMPLEMENTS = "implements"
    OBSERVES = "observes"
    FLOWS_TO = "flows_to"
    CALLS = "calls"
    REQUIRES_SCOPE = "requires_scope"
    SIGNED_BY = "signed_by"
    UPDATED_FROM = "updated_from"
    APPROVED_BY = "approved_by"
    HAS_SOURCE_LABEL = "has_source_label"
    HAS_SENSITIVITY = "has_sensitivity"
    HAS_TRUST = "has_trust"
    TARGETS_SINK = "targets_sink"


class AttackClass(str, Enum):
    """Seven compositional attack categories."""
    CAPABILITY_LAUNDERING = "capability_laundering"
    CROSS_SKILL_CONFUSED_DEPUTY = "cross_skill_confused_deputy"
    DELAYED_RUG_PULL = "delayed_rug_pull"
    CONSENT_LAUNDERING = "consent_laundering"
    PERSISTENCE_PIVOT = "persistence_pivot"
    SPLIT_EXFILTRATION = "split_exfiltration"
    SCOPE_INFLATION = "scope_inflation"


class LifecycleStage(str, Enum):
    """Lifecycle boundaries in the skill ecosystem."""
    DISCOVERY = "discovery"
    REGISTRATION = "registration"
    IMPLEMENTATION = "implementation"
    INVOCATION = "invocation"
    RETURN = "return"
    APPROVAL = "approval"
    PERSISTENCE = "persistence"
    UPDATE = "update"


# ---------------------------------------------------------------------------
# Evidence item
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Evidence:
    """A normalized cross-layer security assertion."""
    kind: str
    subject: str
    predicate: str
    object: str
    confidence: float = 1.0
    attrs: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Graph node and edge
# ---------------------------------------------------------------------------

@dataclass
class GraphNode:
    """A typed node in the evidence graph."""
    id: str
    node_type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.node_type.value,
            "properties": self.properties,
        }


@dataclass
class GraphEdge:
    """A typed edge in the evidence graph."""
    source: str
    target: str
    edge_type: EdgeType
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.edge_type.value,
            "properties": self.properties,
        }


# ---------------------------------------------------------------------------
# Finding and risk report
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A policy finding produced by graph constraints."""
    constraint: str
    severity: Severity
    message: str
    evidence: List[Evidence] = field(default_factory=list)
    nodes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "constraint": self.constraint,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": [e.to_dict() for e in self.evidence],
            "nodes": self.nodes,
        }


@dataclass
class RiskReport:
    risk: Severity
    decision: Decision
    findings: List[Finding]
    score: float = 0.0
    evidence_path: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk": self.risk.value,
            "decision": self.decision.value,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "evidence_path": [e.to_dict() for e in self.evidence_path],
        }


# ---------------------------------------------------------------------------
# Benchmark sample schema
# ---------------------------------------------------------------------------

@dataclass
class SkillSample:
    """A benchmark skill sample."""
    case_id: str
    label: str  # "benign" or attack class value
    manifest: Dict[str, Any]
    source_code: Optional[str] = None
    runtime_trace: Optional[Dict[str, Any]] = None
    expected_evidence: List[str] = field(default_factory=list)
    benign_pair: Optional[str] = None
    lifecycle_stages: List[str] = field(default_factory=list)
    attack_class: Optional[str] = None
    success_validator: Optional[str] = None
    platform_type: str = "mcp"

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "case_id": self.case_id,
            "label": self.label,
            "manifest": self.manifest,
            "platform_type": self.platform_type,
            "expected_evidence": self.expected_evidence,
        }
        if self.source_code is not None:
            d["source_code"] = self.source_code
        if self.runtime_trace is not None:
            d["runtime_trace"] = self.runtime_trace
        if self.benign_pair:
            d["benign_pair"] = self.benign_pair
        if self.lifecycle_stages:
            d["lifecycle_stages"] = self.lifecycle_stages
        if self.attack_class:
            d["attack_class"] = self.attack_class
        if self.success_validator:
            d["success_validator"] = self.success_validator
        return d
