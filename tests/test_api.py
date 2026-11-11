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
