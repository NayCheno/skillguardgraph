from __future__ import annotations

from collections import defaultdict
from typing import Dict, Iterable, List

from .models import Evidence


class EvidenceGraph:
    """A lightweight typed evidence graph.

    This intentionally avoids external graph dependencies so the skeleton can run
    in constrained environments. Evidence items are indexed by subject,
    predicate, object, and kind for simple constraint evaluation.
    """

    def __init__(self, evidence: Iterable[Evidence] | None = None) -> None:
        self.evidence: List[Evidence] = []
        self.by_subject: Dict[str, List[Evidence]] = defaultdict(list)
        self.by_predicate: Dict[str, List[Evidence]] = defaultdict(list)
        self.by_object: Dict[str, List[Evidence]] = defaultdict(list)
        self.by_kind: Dict[str, List[Evidence]] = defaultdict(list)
        if evidence:
            for item in evidence:
                self.add(item)

    def add(self, item: Evidence) -> None:
        self.evidence.append(item)
        self.by_subject[item.subject].append(item)
        self.by_predicate[item.predicate].append(item)
        self.by_object[item.object].append(item)
        self.by_kind[item.kind].append(item)

    def extend(self, items: Iterable[Evidence]) -> None:
        for item in items:
            self.add(item)

    def find(
        self,
        *,
        kind: str | None = None,
        subject: str | None = None,
        predicate: str | None = None,
        object: str | None = None,
    ) -> List[Evidence]:
        candidates = self.evidence
        if kind is not None:
            candidates = self.by_kind.get(kind, [])
        if subject is not None:
            candidates = [e for e in candidates if e.subject == subject]
        if predicate is not None:
            candidates = [e for e in candidates if e.predicate == predicate]
        if object is not None:
            candidates = [e for e in candidates if e.object == object]
        return list(candidates)

    def subjects_with(self, predicate: str, object: str | None = None) -> set[str]:
        return {
            e.subject
            for e in self.find(predicate=predicate)
            if object is None or e.object == object
        }
