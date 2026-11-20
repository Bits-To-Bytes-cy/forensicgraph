import io
import json
from datetime import UTC, datetime
from pathlib import Path

from forensicgraph.models import (
    Membership,
    Organization,
    ProcessingError,
    ProcessingRun,
    RawRecord,
    User,
)
from forensicgraph.services import evidence as evidence_service
from forensicgraph.services import processing as processing_service
from forensicgraph.services.auth import issue_access_token

from tests.conftest import TestingSession


class FakeStorage:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put_file(self, key: str, path: Path, content_type: str) -> None:
        self.objects[key] = path.read_bytes()

    def copy(self, source_key: str, destination_key: str) -> None:
        self.objects[destination_key] = self.objects[source_key]

    def exists(self, key: str) -> bool:
        return key in self.objects

    def read(self, key: str):
        yield self.objects[key]

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)


def setup_case(client, user_id: str, slug: str, storage):
    with TestingSession() as session:
        organization = Organization(
            id=f"org-{slug}",
            name="Processing Organization",
            slug=slug,
            created_at=datetime.now(UTC),
        )
        session.add(organization)
        session.add(
            Membership(
                id=f"membership-{slug}",
                organization_id=organization.id,
                user_id=user_id,
                role="owner",
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
    headers = {"Authorization": f"Bearer {issue_access_token(user_id)}"}
    case = client.post(
        f"/api/v1/organizations/org-{slug}/cases",
        headers=headers,
        json={"title": "Processing case"},
    ).json()
    payload = (
        b'[{"createdDateTime":"2026-01-01T00:00:00Z","userPrincipalName":"alice",'
        b'"ipAddress":"10.0.0.1"},'
        b'{"createdDateTime":"2026-01-01T00:01:00Z","userPrincipalName":"bob",'
        b'"ipAddress":"10.0.0.2"}]'
    )
    started = client.post(
        f"/api/v1/cases/{case['id']}/evidence/uploads",
        headers=headers,
        json={
            "original_filename": "signin.json",
            "media_type": "application/json",
            "expected_size": len(payload),
        },
    ).json()
    client.put(
        f"/api/v1/evidence/uploads/{started['id']}/content",
        headers=headers,
        files={"file": ("signin.json", io.BytesIO(payload), "application/json")},
    )
    evidence = client.post(
        f"/api/v1/evidence/uploads/{started['id']}/complete", headers=headers
    ).json()
    return headers, case, evidence


def test_ingestion_preserves_raw_records_and_duplicate_processing(
    client, seeded_user, monkeypatch
):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    monkeypatch.setattr(processing_service, "get_storage", lambda: storage)
    headers, case, evidence = setup_case(
        client, seeded_user.id, "processing-org", storage
    )

    response = client.post(
        f"/api/v1/evidence/{evidence['id']}/ingest",
        headers=headers,
        json={"parser_name": "entra_signin", "batch_size": 1},
    )
    assert response.status_code == 201
    run = response.json()
    assert run["status"] == "completed", run["error_summary"]
    assert run["processed_records"] == 2
    duplicate = client.post(
        f"/api/v1/evidence/{evidence['id']}/ingest",
        headers=headers,
        json={"parser_name": "entra_signin"},
    )
    assert duplicate.json()["id"] == run["id"]
    with TestingSession() as session:
        raw = list(session.query(RawRecord).all())
        assert len(raw) == 2
        assert raw[0].evidence_id == evidence["id"]
        assert raw[0].processing_run_id == run["id"]
        assert json.loads(raw[0].raw_payload)["userPrincipalName"] == "alice"

    listed = client.get(f"/api/v1/cases/{case['id']}/processing-runs", headers=headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_reprocessing_creates_new_attempt_and_errors_are_exposed(
    client, seeded_user, monkeypatch
):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    monkeypatch.setattr(processing_service, "get_storage", lambda: storage)
    headers, _, evidence = setup_case(client, seeded_user.id, "reprocess-org", storage)
    first = client.post(
        f"/api/v1/evidence/{evidence['id']}/ingest",
        headers=headers,
        json={"parser_name": "entra_signin"},
    ).json()
    second = client.post(
        f"/api/v1/evidence/{evidence['id']}/ingest",
        headers=headers,
        json={"parser_name": "entra_signin", "reprocess": True},
    ).json()
    assert second["attempt"] == first["attempt"] + 1
    assert second["id"] != first["id"]

    with TestingSession() as session:
        run = session.get(ProcessingRun, second["id"])
        run.status = "failed"
        session.add(
            ProcessingError(
                id="processing-error",
                processing_run_id=run.id,
                evidence_id=run.evidence_id,
                case_id=run.case_id,
                organization_id=run.organization_id,
                source_locator="line:9",
                error_type="malformed_record",
                message="bad record",
                details="{}",
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
    errors = client.get(
        f"/api/v1/processing-runs/{second['id']}/errors", headers=headers
    )
    assert errors.status_code == 200
    assert any(error["source_locator"] == "line:9" for error in errors.json())


def test_unsupported_parser_and_cross_tenant_run_are_denied(
    client, seeded_user, monkeypatch
):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    monkeypatch.setattr(processing_service, "get_storage", lambda: storage)
    headers, _, evidence = setup_case(
        client, seeded_user.id, "authorization-org", storage
    )
    unsupported = client.post(
        f"/api/v1/evidence/{evidence['id']}/ingest",
        headers=headers,
        json={"parser_name": "m365_unified_audit"},
    )
    assert unsupported.status_code == 201
    assert unsupported.json()["status"] == "failed"
    with TestingSession() as session:
        outsider = User(
            id="processing-outsider",
            email="processing-outsider@example.com",
            display_name="Outsider",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        session.add(outsider)
        session.commit()
    outsider_headers = {
        "Authorization": f"Bearer {issue_access_token('processing-outsider')}"
    }
    response = client.post(
        f"/api/v1/evidence/{evidence['id']}/ingest",
        headers=outsider_headers,
        json={"parser_name": "entra_signin"},
    )
    assert response.status_code == 404
