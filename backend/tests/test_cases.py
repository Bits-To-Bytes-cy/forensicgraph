from datetime import UTC, datetime

from forensicgraph.models import Membership, Organization, User
from forensicgraph.services.auth import issue_access_token

from tests.conftest import TestingSession


def create_org_for_user(user_id: str, slug: str = "case-org") -> str:
    with TestingSession() as session:
        organization = Organization(
            id=f"org-{slug}",
            name="Case Organization",
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
        return organization.id


def test_case_creation_numbering_creator_and_history(client, seeded_user):
    organization_id = create_org_for_user(seeded_user.id)
    headers = {"Authorization": f"Bearer {issue_access_token(seeded_user.id)}"}

    first = client.post(
        f"/api/v1/organizations/{organization_id}/cases",
        headers=headers,
        json={"title": "First investigation", "scope": "Identity"},
    )
    second = client.post(
        f"/api/v1/organizations/{organization_id}/cases",
        headers=headers,
        json={"title": "Second investigation"},
    )
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["case_number"] == 1
    assert second.json()["case_number"] == 2
    assert first.json()["status"] == "draft"

    members = client.get(f"/api/v1/cases/{first.json()['id']}/members", headers=headers)
    assert members.json()[0]["role"] == "case_lead"
    history = client.get(f"/api/v1/cases/{first.json()['id']}/history", headers=headers)
    assert history.json()[0]["to_status"] == "draft"


def test_case_roles_invalid_membership_escalation_and_removal(client, seeded_user):
    organization_id = create_org_for_user(seeded_user.id, "roles-org")
    with TestingSession() as session:
        investigator = User(
            id="investigator",
            email="investigator@example.com",
            display_name="Investigator",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        reviewer = User(
            id="reviewer",
            email="reviewer@example.com",
            display_name="Reviewer",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        session.add_all([investigator, reviewer])
        session.add(
            Membership(
                id="investigator-membership",
                organization_id=organization_id,
                user_id=investigator.id,
                role="member",
                created_at=datetime.now(UTC),
            )
        )
        session.add(
            Membership(
                id="reviewer-membership",
                organization_id=organization_id,
                user_id=reviewer.id,
                role="member",
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
    owner_headers = {"Authorization": f"Bearer {issue_access_token(seeded_user.id)}"}
    case = client.post(
        f"/api/v1/organizations/{organization_id}/cases",
        headers=owner_headers,
        json={"title": "Role investigation"},
    ).json()

    assigned = client.post(
        f"/api/v1/cases/{case['id']}/members",
        headers=owner_headers,
        json={"user_id": "investigator", "role": "investigator"},
    )
    assert assigned.status_code == 201
    reviewer_assigned = client.post(
        f"/api/v1/cases/{case['id']}/members",
        headers=owner_headers,
        json={"user_id": "reviewer", "role": "reviewer"},
    )
    assert reviewer_assigned.status_code == 201

    # Owner can assign a second lead, allowing safe removal of the first.
    lead = client.post(
        f"/api/v1/cases/{case['id']}/members",
        headers=owner_headers,
        json={"user_id": "reviewer", "role": "case_lead"},
    )
    assert lead.status_code == 409
    last_lead = client.delete(
        f"/api/v1/cases/{case['id']}/members/{seeded_user.id}",
        headers=owner_headers,
    )
    assert last_lead.status_code == 409


def test_case_workflow_closure_archival_and_invalid_transition(client, seeded_user):
    organization_id = create_org_for_user(seeded_user.id, "workflow-org")
    headers = {"Authorization": f"Bearer {issue_access_token(seeded_user.id)}"}
    case = client.post(
        f"/api/v1/organizations/{organization_id}/cases",
        headers=headers,
        json={"title": "Workflow investigation"},
    ).json()
    case_url = f"/api/v1/cases/{case['id']}"

    assert (
        client.post(
            f"{case_url}/status", headers=headers, json={"status": "closed"}
        ).status_code
        == 409
    )
    for status in (
        "open",
        "under_investigation",
        "pending_review",
        "closed",
        "archived",
    ):
        response = client.post(
            f"{case_url}/status", headers=headers, json={"status": status}
        )
        assert response.status_code == 200
    assert response.json()["archived_at"] is not None
    assert (
        client.patch(case_url, headers=headers, json={"title": "No edit"}).status_code
        == 409
    )


def test_case_cross_organization_access_is_denied(client, seeded_user):
    organization_id = create_org_for_user(seeded_user.id, "private-org")
    headers = {"Authorization": f"Bearer {issue_access_token(seeded_user.id)}"}
    case = client.post(
        f"/api/v1/organizations/{organization_id}/cases",
        headers=headers,
        json={"title": "Private"},
    ).json()
    with TestingSession() as session:
        outsider = User(
            id="outsider",
            email="outsider@example.com",
            display_name="Outsider",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        other_org = Organization(
            id="other-org",
            name="Other",
            slug="other-org",
            created_at=datetime.now(UTC),
        )
        session.add_all([outsider, other_org])
        session.add(
            Membership(
                id="outsider-membership",
                organization_id=other_org.id,
                user_id=outsider.id,
                role="owner",
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
    outsider_headers = {"Authorization": f"Bearer {issue_access_token('outsider')}"}
    response = client.get(
        f"/api/v1/organizations/{organization_id}/cases/{case['id']}",
        headers=outsider_headers,
    )
    assert response.status_code == 404
