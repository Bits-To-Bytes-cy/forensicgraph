"""SQLite-backed case and event storage for repeatable investigations."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from forensicgraph.timeline import custody_digest


class CaseStore:
    def __init__(self, path: str) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = Lock()
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                events_json TEXT NOT NULL DEFAULT '[]',
                report_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS custody (
                sequence INTEGER PRIMARY KEY,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                previous_digest TEXT NOT NULL,
                digest TEXT NOT NULL UNIQUE
            );
            """
        )
        self._connection.commit()

    def create_case(self, case_id: str, title: str, description: str) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO cases(case_id, title, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (case_id, title, description, now, now),
            )
            self._connection.commit()
        return self.get_case(case_id)

    def upsert_events(self, case_id: str, events: list[dict[str, Any]]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._connection.execute(
                """
                UPDATE cases SET events_json = ?, updated_at = ? WHERE case_id = ?
                """,
                (json.dumps(events, default=str), now, case_id),
            )
            self._connection.commit()
        return self.get_case(case_id)

    def save_report(self, case_id: str, report: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._connection.execute(
                """
                UPDATE cases SET report_json = ?, updated_at = ? WHERE case_id = ?
                """,
                (json.dumps(report, default=str), now, case_id),
            )
            self._connection.commit()
        return self.get_case(case_id)

    def get_case(self, case_id: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if row is None:
            raise KeyError(case_id)
        return self._decode(row)

    def list_cases(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM cases ORDER BY updated_at DESC"
        ).fetchall()
        return [self._decode(row) for row in rows]

    def append_custody(
        self, action: str, actor: str, evidence_id: str
    ) -> dict[str, Any]:
        recorded_at = datetime.now(timezone.utc)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            previous = self._connection.execute(
                "SELECT digest FROM custody ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_digest = previous["digest"] if previous else "0" * 64
            sequence_row = self._connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM custody"
            ).fetchone()
            sequence = sequence_row["next_sequence"]
            digest = custody_digest(
                sequence=sequence,
                action=action,
                actor=actor,
                evidence_id=evidence_id,
                recorded_at=recorded_at,
                previous_digest=previous_digest,
            )
            self._connection.execute(
                """
                INSERT INTO custody(sequence, action, actor, evidence_id, recorded_at,
                                    previous_digest, digest)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    action,
                    actor,
                    evidence_id,
                    recorded_at.isoformat(),
                    previous_digest,
                    digest,
                ),
            )
            self._connection.commit()
        return {
            "sequence": sequence,
            "action": action,
            "actor": actor,
            "evidence_id": evidence_id,
            "recorded_at": recorded_at,
            "previous_digest": previous_digest,
            "digest": digest,
        }

    def list_custody(self) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT * FROM custody ORDER BY sequence"
        ).fetchall()
        return [dict(row) for row in rows]

    def verify_custody(self) -> dict[str, bool | int]:
        entries = self.list_custody()
        previous_digest = "0" * 64
        for entry in entries:
            recorded_at = datetime.fromisoformat(entry["recorded_at"])
            expected = custody_digest(
                sequence=entry["sequence"],
                action=entry["action"],
                actor=entry["actor"],
                evidence_id=entry["evidence_id"],
                recorded_at=recorded_at,
                previous_digest=previous_digest,
            )
            if (
                entry["previous_digest"] != previous_digest
                or entry["digest"] != expected
            ):
                return {"valid": False, "entries": len(entries)}
            previous_digest = entry["digest"]
        return {"valid": True, "entries": len(entries)}

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "case_id": row["case_id"],
            "title": row["title"],
            "description": row["description"],
            "events": json.loads(row["events_json"]),
            "report": json.loads(row["report_json"]) if row["report_json"] else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
