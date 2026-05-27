from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .models import Evidence


@dataclass
class SandboxObservation:
    skill: str
    behavior: str
    target: str
    confidence: float = 0.8


def observations_to_evidence(observations: List[SandboxObservation]) -> List[Evidence]:
    """Convert safe sandbox observations into evidence.

    This module is a placeholder. A real implementation should only run in an
    isolated environment with fake credentials, synthetic data, and blocked or
    sinkholed egress.
    """

    evidence: List[Evidence] = []
    for obs in observations:
        evidence.append(
            Evidence(
                kind="sandbox",
                subject=obs.skill,
                predicate="observes_behavior",
                object=obs.behavior,
                confidence=obs.confidence,
                attrs={"target": obs.target},
            )
        )
    return evidence
