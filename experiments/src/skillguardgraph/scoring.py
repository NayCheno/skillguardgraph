from __future__ import annotations

from .models import Finding, Severity

SEVERITY_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 10,
}


def aggregate_score(findings: list[Finding]) -> float:
    """Return a bounded 0-10 risk score from findings."""
    if not findings:
        return 0.0
    score = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    return min(10.0, float(score))
