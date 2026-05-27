"""SkillGuardGraph cross-layer evidence fusion framework."""
__version__ = "0.2.0"

from .models import (
    AttackClass, Decision, EdgeType, Evidence, Finding, GraphEdge, GraphNode,
    LifecycleStage, NodeType, RiskReport, Severity, SkillSample,
)
from .evidence_graph import EvidenceGraph
from .metadata_analyzer import analyze_manifest, load_manifest
from .runtime_monitor import load_trace, trace_to_evidence
from .policy_engine import evaluate
from .static_analyzer import analyze_source
from .simulated_prober import probe_skill, probe_skill_as_evidence, observations_to_evidence
from .fusion import fuse_and_evaluate, fuse_from_evidence_list
from .baselines import BASELINES, run_all_baselines
