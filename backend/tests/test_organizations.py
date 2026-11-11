from forensicgraph.models import User
from forensicgraph.services.auth import issue_access_token

from tests.conftest import TestingSession


def test_organization_owner_and_tenant_isolation(client, seeded_user):
    token = issue_access_token(seeded_user.id)
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post(
        "/api/v1/organizations",
        headers=headers,
        json={"name": "Acme", "slug": "acme"},
    )
    assert created.status_code == 201
    organization_id = created.json()["id"]

    listed = client.get("/api/v1/organizations", headers=headers)
    assert [item["id"] for item in listed.json()] == [organization_id]

    forbidden = client.get(
        "/api/v1/organizations/not-your-tenant",
        headers=headers,
    )
    assert forbidden.status_code == 404


def test_organization_requires_authentication(client):
    assert client.get("/api/v1/organizations").status_code == 401


def test_cross_tenant_member_cannot_read_other_organization(client, seeded_user):
    with TestingSession() as session:
        other = User(
            id="user-2",
            email="other@example.com",
            display_name="Other",
            is_active=True,
            created_at=__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ),
        )
        session.add(other)
        session.commit()
    owner_headers = {"Authorization": f"Bearer {issue_access_token(seeded_user.id)}"}
    created = client.post(
        "/api/v1/organizations",
        headers=owner_headers,
        json={"name": "Private", "slug": "private"},
    ).json()
    other_headers = {"Authorization": f"Bearer {issue_access_token('user-2')}"}
    response = client.get(
        f"/api/v1/organizations/{created['id']}", headers=other_headers
    )
    assert response.status_code == 404
