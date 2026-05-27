from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Decision(str, Enum):
    ALLOW = "allow"
    DEGRADE = "degrade"
    HITL = "hitl"
    DENY = "deny"
    QUARANTINE = "quarantine"
    ROLLBACK = "rollback"


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


@dataclass
class Finding:
    """A policy finding produced by graph constraints."""

    constraint: str
    severity: Severity
    decision: Decision
    summary: str
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "constraint": self.constraint,
            "severity": self.severity.value,
            "decision": self.decision.value,
            "summary": self.summary,
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class RiskReport:
    risk: Severity
    decision: Decision
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk": self.risk.value,
            "decision": self.decision.value,
            "findings": [f.to_dict() for f in self.findings],
        }
