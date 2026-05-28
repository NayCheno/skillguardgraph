from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from .models import Evidence


def load_trace(path: str | Path) -> Dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def trace_to_evidence(trace: Dict[str, Any]) -> List[Evidence]:
    """Normalize a safe runtime trace into evidence items.

    Expected trace format is intentionally simple and synthetic:

    {
      "trace_id": "...",
      "events": [
        {"id": "e1", "type": "source", "label": "untrusted", ...},
        {"id": "e2", "type": "tool_call", "tool": "...", ...}
      ],
      "flows": [{"from": "e1", "to": "e2"}]
    }
    """

    evidence: List[Evidence] = []
    trace_id = str(trace.get("trace_id", "trace"))
    events = {str(e.get("id")): e for e in trace.get("events", [])}

    for event_id, event in events.items():
        event_type = str(event.get("type", "event"))
        subject = f"{trace_id}:{event_id}"
        label = str(event.get("label", ""))

        if event_type == "source":
            evidence.append(
                Evidence(
                    kind="runtime",
                    subject=subject,
                    predicate="has_source_label",
                    object=label,
                    confidence=0.9,
                    attrs=event,
                )
            )

        if event_type == "tool_call":
            tool = str(event.get("tool", "unknown_tool"))
            evidence.append(
                Evidence(
                    kind="runtime",
                    subject=subject,
                    predicate="calls_tool",
                    object=tool,
                    confidence=0.9,
                    attrs=event,
                )
            )
            if event.get("privilege") == "high":
                evidence.append(
                    Evidence(
                        kind="runtime",
                        subject=subject,
                        predicate="is_high_privilege_call",
                        object=tool,
                        confidence=0.9,
                        attrs=event,
                    )
                )

        if event_type == "data":
            data_label = str(event.get("sensitivity", "unknown"))
            evidence.append(
                Evidence(
                    kind="runtime",
                    subject=subject,
                    predicate="has_data_label",
                    object=data_label,
                    confidence=0.9,
                    attrs=event,
                )
            )

        if event_type == "sink":
            sink_label = str(event.get("sink") or event.get("sink_type") or "unknown_sink")
            evidence.append(
                Evidence(
                    kind="runtime",
                    subject=subject,
                    predicate="is_sink",
                    object=sink_label,
                    confidence=0.9,
                    attrs=event,
                )
            )
            if event.get("external") is True or event.get("is_external") is True:
                evidence.append(
                    Evidence(
                        kind="runtime",
                        subject=subject,
                        predicate="is_external_sink",
                        object=sink_label,
                        confidence=0.9,
                        attrs=event,
                    )
                )

        if event_type == "approval":
            lineage = str(event.get("lineage", "unknown"))
            evidence.append(
                Evidence(
                    kind="approval",
                    subject=subject,
                    predicate="approval_text_lineage",
                    object=lineage,
                    confidence=0.85,
                    attrs=event,
                )
            )

        if event_type == "persistence_write":
            store = str(event.get("target", event.get("store", "unknown_store")))
            sensitivity = str(event.get("sensitivity", "high")).lower()
            label = str(event.get("label", "external")).lower()
            # Low-sensitivity internal persistence is much less suspicious
            if sensitivity == "low" and label in ("internal", "local"):
                conf = 0.3
            elif sensitivity == "low" or label in ("internal", "local"):
                conf = 0.5
            else:
                conf = 0.9
            evidence.append(
                Evidence(
                    kind="runtime",
                    subject=subject,
                    predicate="writes_persistent_store",
                    object=store,
                    confidence=conf,
                    attrs=event,
                )
            )
        if event_type == "version_update":
            drift_level = str(event.get("drift_level", "high"))
            evidence.append(
                Evidence(
                    kind="runtime",
                    subject=subject,
                    predicate="post_approval_drift",
                    object=drift_level,
                    confidence=float(event.get("confidence", 0.85)),
                    attrs=event,
                )
            )
            if event.get("high_risk_addition") or drift_level == "high":
                evidence.append(
                    Evidence(
                        kind="runtime",
                        subject=subject,
                        predicate="high_risk_version_change",
                        object=str(event.get("new_capabilities", "unknown")),
                        confidence=0.9,
                        attrs=event,
                    )
                )
    for flow in trace.get("flows", []):
        src = str(flow.get("from"))
        dst = str(flow.get("to"))
        if src in events and dst in events:
            evidence.append(
                Evidence(
                    kind="runtime",
                    subject=f"{trace_id}:{src}",
                    predicate="flows_to",
                    object=f"{trace_id}:{dst}",
                    confidence=float(flow.get("confidence", 0.8)),
                    attrs={"trace_id": trace_id},
                )
            )

    return evidence
