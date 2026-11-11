from forensicgraph.services.auth import issue_access_token, issue_refresh_token

from tests.conftest import TestingSession


def test_refresh_rotation_and_revocation(client, seeded_user):
    with TestingSession() as session:
        refresh = issue_refresh_token(session, seeded_user.id)

    first = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert first.status_code == 200
    assert first.json()["refresh_token"] != refresh

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert replay.status_code == 401

    logout = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": first.json()["refresh_token"]},
    )
    assert logout.status_code == 204
    revoked = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": first.json()["refresh_token"]},
    )
    assert revoked.status_code == 401


def test_invalid_state_is_rejected(client):
    response = client.get(
        "/api/v1/auth/callback?code=unused&state=invalid",
    )
    assert response.status_code == 400


def test_login_has_no_development_bypass(client):
    response = client.post("/api/v1/auth/login")
    assert response.status_code == 503


def test_access_token_and_me_are_user_scoped(client, seeded_user):
    token = issue_access_token(seeded_user.id)

    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["email"] == seeded_user.email
