import hashlib
import io
from datetime import UTC, datetime
from pathlib import Path

from forensicgraph.models import EvidenceItem, Membership, Organization, User
from forensicgraph.services import evidence as evidence_service
from forensicgraph.services.auth import issue_access_token

from tests.conftest import TestingSession


class FakeStorage:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.fail_copy = False

    def put_file(self, key: str, path: Path, content_type: str) -> None:
        self.objects[key] = path.read_bytes()

    def copy(self, source_key: str, destination_key: str) -> None:
        if self.fail_copy:
            raise OSError("storage unavailable")
        self.objects[destination_key] = self.objects[source_key]

    def exists(self, key: str) -> bool:
        return key in self.objects

    def read(self, key: str):
        yield self.objects[key]

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)


def create_case(client, user_id: str, slug: str) -> tuple[str, dict, dict]:
    with TestingSession() as session:
        organization = Organization(
            id=f"org-{slug}",
            name="Evidence Organization",
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
    response = client.post(
        f"/api/v1/organizations/org-{slug}/cases",
        headers=headers,
        json={"title": "Evidence investigation"},
    )
    assert response.status_code == 201
    return organization.id, response.json(), headers


def test_evidence_upload_hashes_readback_and_download(client, seeded_user, monkeypatch):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    _, case, headers = create_case(client, seeded_user.id, "evidence-org")
    content = b"forensic evidence bytes\n"
    started = client.post(
        f"/api/v1/cases/{case['id']}/evidence/uploads",
        headers=headers,
        json={
            "original_filename": "capture.bin",
            "media_type": "application/octet-stream",
            "expected_size": len(content),
        },
    )
    assert started.status_code == 201
    upload_id = started.json()["id"]
    uploaded = client.put(
        f"/api/v1/evidence/uploads/{upload_id}/content",
        headers=headers,
        files={
            "file": ("capture.bin", io.BytesIO(content), "application/octet-stream")
        },
    )
    assert uploaded.status_code == 200
    completed = client.post(
        f"/api/v1/evidence/uploads/{upload_id}/complete", headers=headers
    )
    assert completed.status_code == 200
    evidence = completed.json()
    assert evidence["sha256"] == hashlib.sha256(content).hexdigest()
    assert evidence["sha512"] == hashlib.sha512(content).hexdigest()
    assert (
        client.get(
            f"/api/v1/evidence/{evidence['id']}/download", headers=headers
        ).content
        == content
    )
    verified = client.post(f"/api/v1/evidence/{evidence['id']}/verify", headers=headers)
    assert verified.status_code == 200
    assert verified.json()["hashes_match"] is True
    assert verified.json()["storage_readback"] is True


def test_one_byte_modification_and_chain_tampering_are_reported(
    client, seeded_user, monkeypatch
):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    _, case, headers = create_case(client, seeded_user.id, "tamper-org")
    content = b"original"
    started = client.post(
        f"/api/v1/cases/{case['id']}/evidence/uploads",
        headers=headers,
        json={
            "original_filename": "original.bin",
            "media_type": "application/octet-stream",
        },
    ).json()
    client.put(
        f"/api/v1/evidence/uploads/{started['id']}/content",
        headers=headers,
        files={
            "file": ("original.bin", io.BytesIO(content), "application/octet-stream")
        },
    )
    evidence = client.post(
        f"/api/v1/evidence/uploads/{started['id']}/complete", headers=headers
    ).json()
    with TestingSession() as session:
        storage_key = session.get(EvidenceItem, evidence["id"]).storage_key
    storage.objects[storage_key] = b"modifled"
    modified = client.post(f"/api/v1/evidence/{evidence['id']}/verify", headers=headers)
    assert modified.status_code == 200
    assert modified.json()["hashes_match"] is False

    with TestingSession() as session:
        event = session.query(evidence_service.EvidenceCustodyEvent).first()
        event.payload = '{"tampered":true}'
        session.commit()
    chain = client.post(f"/api/v1/evidence/{evidence['id']}/verify", headers=headers)
    assert chain.status_code == 200
    assert chain.json()["chain_valid"] is False


def test_interrupted_upload_storage_recovery_and_derivative(
    client, seeded_user, monkeypatch
):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    _, case, headers = create_case(client, seeded_user.id, "recovery-org")
    started = client.post(
        f"/api/v1/cases/{case['id']}/evidence/uploads",
        headers=headers,
        json={
            "original_filename": "recovery.bin",
            "media_type": "application/octet-stream",
        },
    ).json()
    assert (
        client.post(
            f"/api/v1/evidence/uploads/{started['id']}/complete", headers=headers
        ).status_code
        == 409
    )
    content = b"recoverable"
    client.put(
        f"/api/v1/evidence/uploads/{started['id']}/content",
        headers=headers,
        files={
            "file": ("recovery.bin", io.BytesIO(content), "application/octet-stream")
        },
    )
    storage.fail_copy = True
    assert (
        client.post(
            f"/api/v1/evidence/uploads/{started['id']}/complete", headers=headers
        ).status_code
        == 503
    )
    storage.fail_copy = False
    evidence = client.post(
        f"/api/v1/evidence/uploads/{started['id']}/complete", headers=headers
    ).json()
    derivative = client.post(
        f"/api/v1/evidence/{evidence['id']}/derivatives",
        headers=headers,
        data={"purpose": "normalized working copy"},
        files={"file": ("working.txt", io.BytesIO(b"working"), "text/plain")},
    )
    assert derivative.status_code == 201
    assert (
        client.get(
            f"/api/v1/evidence/{evidence['id']}/derivatives", headers=headers
        ).json()[0]["purpose"]
        == "normalized working copy"
    )


def test_reconciliation_marks_missing_quarantine_objects(
    client, seeded_user, monkeypatch
):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    _, case, headers = create_case(client, seeded_user.id, "reconcile-org")
    started = client.post(
        f"/api/v1/cases/{case['id']}/evidence/uploads",
        headers=headers,
        json={
            "original_filename": "lost.bin",
            "media_type": "application/octet-stream",
        },
    ).json()
    with TestingSession() as session:
        result = evidence_service.reconcile_evidence_storage(session)
        assert result == {"checked": 1, "failed": 1}
        upload = session.get(evidence_service.EvidenceUploadSession, started["id"])
        assert upload.status == "failed"


def test_evidence_tenant_isolation(client, seeded_user, monkeypatch):
    storage = FakeStorage()
    monkeypatch.setattr(evidence_service, "get_storage", lambda: storage)
    _, case, headers = create_case(client, seeded_user.id, "tenant-evidence-org")
    started = client.post(
        f"/api/v1/cases/{case['id']}/evidence/uploads",
        headers=headers,
        json={
            "original_filename": "private.bin",
            "media_type": "application/octet-stream",
        },
    ).json()
    client.put(
        f"/api/v1/evidence/uploads/{started['id']}/content",
        headers=headers,
        files={
            "file": ("private.bin", io.BytesIO(b"private"), "application/octet-stream")
        },
    )
    evidence = client.post(
        f"/api/v1/evidence/uploads/{started['id']}/complete", headers=headers
    ).json()
    with TestingSession() as session:
        outsider = User(
            id="evidence-outsider",
            email="evidence-outsider@example.com",
            display_name="Outsider",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        session.add(outsider)
        session.commit()
    outsider_headers = {
        "Authorization": f"Bearer {issue_access_token('evidence-outsider')}"
    }
    assert (
        client.get(
            f"/api/v1/evidence/{evidence['id']}", headers=outsider_headers
        ).status_code
        == 404
    )
