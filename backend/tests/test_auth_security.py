from datetime import UTC, datetime, timedelta

import jwt
import pytest
from forensicgraph.config import settings
from forensicgraph.services.auth import _validate_claims


def test_expired_oidc_token_is_rejected(monkeypatch):
    token = jwt.encode(
        {
            "sub": "subject-1",
            "iss": settings.oidc_issuer,
            "aud": settings.oidc_client_id,
            "iat": datetime.now(UTC) - timedelta(hours=2),
            "exp": datetime.now(UTC) - timedelta(hours=1),
            "nonce": "nonce",
        },
        settings.app_secret_key,
        algorithm="HS256",
    )

    class KeyClient:
        def __init__(self, _url):
            pass

        def get_signing_key_from_jwt(self, _token):
            return type("Key", (), {"key": settings.app_secret_key})()

    monkeypatch.setattr(jwt, "PyJWKClient", KeyClient)
    monkeypatch.setattr(settings, "oidc_issuer", "https://issuer.example")
    monkeypatch.setattr(settings, "oidc_client_id", "client")

    with pytest.raises(Exception, match="Invalid OIDC identity token|expired"):
        _validate_claims(token, {"jwks_uri": "https://issuer.example/jwks"}, "nonce")


def test_nonce_mismatch_is_rejected(monkeypatch):
    token = "signed-token"

    class KeyClient:
        def __init__(self, _url):
            pass

        def get_signing_key_from_jwt(self, _token):
            return type("Key", (), {"key": "unused"})()

    monkeypatch.setattr(jwt, "PyJWKClient", KeyClient)
    monkeypatch.setattr(
        jwt,
        "decode",
        lambda *_args, **_kwargs: {
            "sub": "subject-1",
            "iss": "https://issuer.example",
            "aud": "client",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            "nonce": "different",
        },
    )
    monkeypatch.setattr(settings, "oidc_issuer", "https://issuer.example")
    monkeypatch.setattr(settings, "oidc_client_id", "client")

    with pytest.raises(Exception, match="nonce"):
        _validate_claims(token, {"jwks_uri": "https://issuer.example/jwks"}, "expected")
