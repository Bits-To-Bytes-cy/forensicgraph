"""Explainable attack-path analysis for normalized investigation events."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


_HIGH_RISK_EVENTS = {
    "privilege_escalation": 35,
    "credential_access": 30,
    "mass_download": 30,
    "ransomware_activity": 40,
}


def analyze_attack_graph(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a deterministic graph and explainable findings from event details.

    Event details may provide ``source_node`` and ``target_node``. Events without
    both fields remain useful as risk findings but cannot form a graph edge.
    """
    nodes: set[str] = set()
    edges: list[dict[str, str]] = []
    risk_by_actor: defaultdict[str, int] = defaultdict(int)
    findings: list[dict[str, Any]] = []

    for event in events:
        details = event.get("details", {})
        source = details.get("source_node")
        target = details.get("target_node")
        actor = event.get("actor") or "unknown"
        event_type = event["event_type"]

        if source and target:
            nodes.update((source, target))
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "event_id": event["event_id"],
                    "event_type": event_type,
                }
            )

        points = _HIGH_RISK_EVENTS.get(event_type, 0)
        if points:
            risk_by_actor[actor] += points
            findings.append(
                {
                    "event_id": event["event_id"],
                    "severity": "high" if points >= 30 else "medium",
                    "reason": f"{event_type} activity detected",
                    "risk_points": points,
                    "actor": actor,
                }
            )

    return {
        "nodes": [{"id": node} for node in sorted(nodes)],
        "edges": sorted(edges, key=lambda edge: (edge["source"], edge["target"], edge["event_id"])),
        "actor_risk": [
            {"actor": actor, "risk_points": points}
            for actor, points in sorted(risk_by_actor.items())
        ],
        "findings": sorted(findings, key=lambda finding: finding["event_id"]),
    }
