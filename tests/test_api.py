from pathlib import Path

from fastapi.testclient import TestClient

from forensicgraph.api import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_hash_evidence_returns_manifest(tmp_path: Path) -> None:
    evidence = tmp_path / "event.log"
    evidence.write_text("synthetic authorized lab evidence\n", encoding="utf-8")

    response = client.post(
        "/v1/evidence/hash",
        json={
            "path": str(evidence),
            "evidence_id": "ev-001",
            "source": "synthetic-endpoint",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["evidence_id"] == "ev-001"
    assert len(body["sha256"]) == 64
    assert body["source"] == "synthetic-endpoint"


def test_hash_evidence_rejects_missing_file() -> None:
    response = client.post(
        "/v1/evidence/hash",
        json={
            "path": "/does/not/exist",
            "evidence_id": "ev-404",
            "source": "synthetic-endpoint",
        },
    )

    assert response.status_code == 404


def test_timeline_reconstructs_events_in_time_order() -> None:
    response = client.post(
        "/v1/timeline/reconstruct",
        json={
            "events": [
                {
                    "event_id": "evt-2",
                    "occurred_at": "2026-01-01T10:01:00Z",
                    "source": "cloudtrail",
                    "event_type": "GetObject",
                },
                {
                    "event_id": "evt-1",
                    "occurred_at": "2026-01-01T10:00:00Z",
                    "source": "auth",
                    "event_type": "Login",
                },
            ]
        },
    )

    assert response.status_code == 200
    assert [event["event_id"] for event in response.json()] == ["evt-1", "evt-2"]


def test_custody_entries_form_a_verifiable_hash_chain() -> None:
    first = client.post(
        "/v1/custody",
        json={"action": "collected", "actor": "analyst-1", "evidence_id": "ev-001"},
    )
    second = client.post(
        "/v1/custody",
        json={"action": "reviewed", "actor": "analyst-2", "evidence_id": "ev-001"},
    )

    assert first.status_code == 200
    assert second.json()["previous_digest"] == first.json()["digest"]
    assert client.get("/v1/custody/verify").json() == {"valid": True, "entries": 2}
