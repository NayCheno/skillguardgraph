"""Typed cross-layer evidence graph.

Supports two construction modes:
1. From a list of Evidence items (legacy / simple path).
2. From typed GraphNode + GraphEdge objects (full graph path).

Both produce a unified structure queryable by the policy engine.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import (
    EdgeType,
    Evidence,
    GraphEdge,
    GraphNode,
    NodeType,
)


class EvidenceGraph:
    """A typed cross-layer evidence graph.

    Evidence items are automatically materialized as typed GraphNode and
    GraphEdge objects, enabling graph-based path queries and reachability.
    """

    _KIND_TO_NODE_TYPE: Dict[str, NodeType] = {
        "metadata": NodeType.METADATA,
        "static": NodeType.CODE_SLICE,
        "sandbox": NodeType.RUNTIME_EVENT,
        "runtime": NodeType.RUNTIME_EVENT,
        "permission": NodeType.METADATA,
        "governance": NodeType.METADATA,
        "approval": NodeType.METADATA,
    }

    _PRED_TO_EDGE_TYPE: Dict[str, EdgeType] = {
        "declares_capability": EdgeType.DECLARES,
        "annotation_claims": EdgeType.DECLARES,
        "requires_scope": EdgeType.REQUIRES_SCOPE,
        "requires_high_risk_scope": EdgeType.REQUIRES_SCOPE,
        "flows_to": EdgeType.FLOWS_TO,
        "calls_tool": EdgeType.CALLS,
        "has_source_label": EdgeType.HAS_SOURCE_LABEL,
        "has_data_label": EdgeType.HAS_SENSITIVITY,
        "post_approval_drift": EdgeType.UPDATED_FROM,
        "high_risk_version_change": EdgeType.UPDATED_FROM,
        "approval_text_lineage": EdgeType.APPROVED_BY,
        "signed_by": EdgeType.SIGNED_BY,
        "is_external_sink": EdgeType.TARGETS_SINK,
        "is_high_privilege_call": EdgeType.CALLS,
        "sandbox_observed_write": EdgeType.OBSERVES,
        "sandbox_observed_network": EdgeType.OBSERVES,
        "sandbox_observed_shell": EdgeType.OBSERVES,
        "sandbox_observed_persistence": EdgeType.OBSERVES,
        "source_identified": EdgeType.IMPLEMENTS,
        "sink_identified": EdgeType.IMPLEMENTS,
        "writes_persistent_store": EdgeType.FLOWS_TO,
        "persists_to": EdgeType.FLOWS_TO,
        "hidden_instruction": EdgeType.DECLARES,
        "scope_inflation": EdgeType.DECLARES,
        "task_context": EdgeType.DECLARES,
    }

    # Object values that are literal labels, not node references
    _LITERAL_OBJECTS = frozenset({
        "read", "write", "search", "query", "list", "summarize",
        "confidential", "secret", "pii", "credential", "public",
        "high", "low", "untrusted", "untrusted_context_only",
        "execution_facts", "read_only_or_low_risk", "data_processing",
        "network_send", "file_write", "shell_exec", "email_send",
        "memory_write", "env_var", "file_read", "database_query",
        "true", "false", "unknown", "none",
    })

    def __init__(
        self,
        evidence: List[Evidence] | None = None,
        nodes: List[GraphNode] | None = None,
        edges: List[GraphEdge] | None = None,
    ) -> None:
        # --- typed graph storage ---
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []
        self._adj_out: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._adj_in: Dict[str, List[GraphEdge]] = defaultdict(list)
        self._edges_by_type: Dict[EdgeType, List[GraphEdge]] = defaultdict(list)

        # --- evidence index ---
        self._evidence: List[Evidence] = list(evidence or [])
        self._pred_index: Dict[str, List[Evidence]] = defaultdict(list)
        self._subject_index: Dict[str, List[Evidence]] = defaultdict(list)

        for ev in self._evidence:
            self._pred_index[ev.predicate].append(ev)
            self._subject_index[ev.subject].append(ev)

        # --- ingest explicit typed nodes/edges ---
        for gn in (nodes or []):
            self._nodes[gn.id] = gn
        for ge in (edges or []):
            self._add_edge(ge)

        # --- materialize typed graph from evidence items ---
        self._materialize_from_evidence()

    # ------------------------------------------------------------------
    # Evidence-to-typed-graph materialization
    # ------------------------------------------------------------------

    def _materialize_from_evidence(self) -> None:
        """Convert Evidence items into typed GraphNode/GraphEdge objects."""
        for ev in self._evidence:
            self._ensure_node(ev.subject, ev.kind)
            # Only create object node if it's a reference, not a literal value
            if ev.object and ev.object.lower() not in self._LITERAL_OBJECTS:
                # Check if it looks like a node ID (contains letters/special chars)
                if any(c.isalpha() or c in ":_-/" for c in ev.object):
                    self._ensure_node(ev.object, ev.kind)
            # Create typed edge
            edge_type = self._PRED_TO_EDGE_TYPE.get(ev.predicate)
            if edge_type is not None:
                target = ev.object if (ev.object and ev.object.lower() not in self._LITERAL_OBJECTS and any(c.isalpha() or c in ":_-/" for c in ev.object)) else ev.subject
                self._add_edge(GraphEdge(
                    source=ev.subject,
                    target=target,
                    edge_type=edge_type,
                    properties={"confidence": ev.confidence},
                ))

    def _ensure_node(self, node_id: str, evidence_kind: str) -> None:
        """Ensure a GraphNode exists for the given ID."""
        if node_id not in self._nodes:
            node_type = self._KIND_TO_NODE_TYPE.get(evidence_kind, NodeType.METADATA)
            self._nodes[node_id] = GraphNode(
                id=node_id,
                node_type=node_type,
                properties={"evidence_kind": evidence_kind},
            )


    # ------------------------------------------------------------------
    # Edge ingestion
    # ------------------------------------------------------------------

    def _add_edge(self, ge: GraphEdge) -> None:
        self._edges.append(ge)
        self._adj_out[ge.source].append(ge)
        self._adj_in[ge.target].append(ge)
        self._edges_by_type[ge.edge_type].append(ge)

    # ------------------------------------------------------------------
    # Backward-compatible interface (policy engine, tests)
    # ------------------------------------------------------------------

    @property
    def evidence(self) -> List[Evidence]:
        return self._evidence

    def find(
        self,
        subject: str | None = None,
        predicate: str | None = None,
        object: str | None = None,
    ) -> List[Evidence]:
        """Query evidence items by subject/predicate/object filters."""
        result = self._evidence
        if subject is not None:
            result = [e for e in result if e.subject == subject]
        if predicate is not None:
            result = [e for e in result if e.predicate == predicate]
        if object is not None:
            result = [e for e in result if e.object == object]
        return result

    # ------------------------------------------------------------------
    # Query helpers (evidence-based)
    # ------------------------------------------------------------------

    def evidence_with_predicate(self, predicate: str) -> List[Evidence]:
        return self._pred_index.get(predicate, [])

    def evidence_for_subject(self, subject: str) -> List[Evidence]:
        return self._subject_index.get(subject, [])

    def subjects_with(self, predicate: str, obj: str | None = None) -> Set[str]:
        items = self._pred_index.get(predicate, [])
        if obj is None:
            return {e.subject for e in items}
        return {e.subject for e in items if e.object == obj}

    def objects_of(self, subject: str, predicate: str) -> Set[str]:
        return {e.object for e in self._subject_index.get(subject, []) if e.predicate == predicate}

    def all_evidence(self) -> List[Evidence]:
        return list(self._evidence)

    # ------------------------------------------------------------------
    # Query helpers (typed graph)
    # ------------------------------------------------------------------

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def nodes_of_type(self, node_type: NodeType) -> List[GraphNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    def node_ids_of_type(self, node_type: NodeType) -> Set[str]:
        return {n.id for n in self._nodes.values() if n.node_type == node_type}

    def edges_of_type(self, edge_type: EdgeType) -> List[GraphEdge]:
        return self._edges_by_type.get(edge_type, [])

    def out_edges(self, node_id: str) -> List[GraphEdge]:
        return self._adj_out.get(node_id, [])

    def in_edges(self, node_id: str) -> List[GraphEdge]:
        return self._adj_in.get(node_id, [])

    def neighbors(self, node_id: str, edge_type: EdgeType | None = None) -> Set[str]:
        result: Set[str] = set()
        for ge in self._adj_out.get(node_id, []):
            if edge_type is None or ge.edge_type == edge_type:
                result.add(ge.target)
        return result

    def predecessors(self, node_id: str, edge_type: EdgeType | None = None) -> Set[str]:
        result: Set[str] = set()
        for ge in self._adj_in.get(node_id, []):
            if edge_type is None or ge.edge_type == edge_type:
                result.add(ge.source)
        return result

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ------------------------------------------------------------------
    # Reachability
    # ------------------------------------------------------------------

    def reachable_from(self, starts: Set[str], max_depth: int = 6) -> Set[str]:
        visited: Set[str] = set()
        frontier = set(starts)
        for _ in range(max_depth):
            next_frontier: Set[str] = set()
            for nid in frontier:
                if nid in visited:
                    continue
                visited.add(nid)
                for ge in self._adj_out.get(nid, []):
                    next_frontier.add(ge.target)
            frontier = next_frontier - visited
        return visited

    def has_path(
        self,
        starts: Set[str],
        targets: Set[str],
        max_depth: int = 6,
    ) -> bool:
        reached = self.reachable_from(starts, max_depth)
        return bool(reached & targets)

    def find_path(
        self,
        start: str,
        target: str,
        max_depth: int = 6,
    ) -> List[str] | None:
        """BFS shortest path from start to target. Returns node IDs or None."""
        if start == target:
            return [start]
        visited: Set[str] = {start}
        queue: list[Tuple[str, List[str]]] = [(start, [start])]
        for _ in range(max_depth):
            next_queue: list[Tuple[str, List[str]]] = []
            for current, path in queue:
                for ge in self._adj_out.get(current, []):
                    if ge.target in visited:
                        continue
                    new_path = path + [ge.target]
                    if ge.target == target:
                        return new_path
                    visited.add(ge.target)
                    next_queue.append((ge.target, new_path))
            queue = next_queue
            if not queue:
                break
        return None

    # ------------------------------------------------------------------
    # Evidence path extraction
    # ------------------------------------------------------------------

    def evidence_path_for(self, node_ids: Set[str]) -> List[Evidence]:
        """Return evidence items whose subjects overlap with the given node IDs."""
        out: List[Evidence] = []
        for ev in self._evidence:
            if ev.subject in node_ids:
                out.append(ev)
        return out[:50]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "evidence": [e.to_dict() for e in self._evidence],
        }
