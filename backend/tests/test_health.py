from fastapi.testclient import TestClient
from forensicgraph.app import app


def healthy_service():
    return type(
        "Health",
        (),
        {"as_dict": lambda self: {"status": "ok", "detail": "test"}},
    )()


def test_health_reports_service_status(monkeypatch) -> None:
    monkeypatch.setattr("forensicgraph.app.check_database", healthy_service)
    monkeypatch.setattr("forensicgraph.app.check_redis", healthy_service)
    monkeypatch.setattr("forensicgraph.app.check_minio", healthy_service)

    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert set(response.json()["services"]) == {"database", "redis", "minio"}
