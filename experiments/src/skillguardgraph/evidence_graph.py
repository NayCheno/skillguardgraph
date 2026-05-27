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
    """A lightweight typed evidence graph.

    Accepts either Evidence items (which are converted to implicit nodes/edges)
    or explicit GraphNode / GraphEdge objects.
    """

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

        # --- evidence index (legacy + graph-sourced) ---
        self._evidence: List[Evidence] = list(evidence or [])
        self._pred_index: Dict[str, List[Evidence]] = defaultdict(list)
        self._subject_index: Dict[str, List[Evidence]] = defaultdict(list)

        for ev in self._evidence:
            self._pred_index[ev.predicate].append(ev)
            self._subject_index[ev.subject].append(ev)

        # --- ingest typed nodes ---
        for gn in (nodes or []):
            self._nodes[gn.id] = gn

        # --- ingest typed edges ---
        for ge in (edges or []):
            self._add_edge(ge)

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
