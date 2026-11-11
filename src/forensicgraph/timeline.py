"""Normalized incident timeline and tamper-evident custody primitives."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def event_sort_key(event: dict[str, Any]) -> tuple[datetime, str]:
    return (event["occurred_at"], event["event_id"])


def reconstruct_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a deterministic timeline without mutating caller-owned events."""
    normalized = [dict(event) for event in events]
    return sorted(normalized, key=event_sort_key)


def custody_digest(
    *,
    sequence: int,
    action: str,
    actor: str,
    evidence_id: str,
    recorded_at: datetime,
    previous_digest: str,
) -> str:
    payload = {
        "sequence": sequence,
        "action": action,
        "actor": actor,
        "evidence_id": evidence_id,
        "recorded_at": recorded_at.isoformat(),
        "previous_digest": previous_digest,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()
