"""Provider-independent OIDC and application-token services."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicgraph.config import settings
from forensicgraph.models.auth import (
    Identity,
    OAuthState,
    RefreshSession,
    User,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _expired(value: datetime) -> bool:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value <= _now()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _pkce_verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()


def _pkce_challenge(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.app_secret_key.encode()).digest()
    )
    return Fernet(key)


def _provider_config() -> dict[str, Any]:
    if not settings.oidc_issuer or not settings.oidc_client_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider is not configured",
        )
    try:
        response = httpx.get(
            f"{settings.oidc_issuer.rstrip('/')}/.well-known/openid-configuration",
            timeout=5,
        )
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC provider discovery failed",
        ) from error
    if document.get("issuer") != settings.oidc_issuer:
        raise HTTPException(status_code=503, detail="OIDC issuer mismatch")
    return document


def begin_login(db: Session) -> str:
    provider = _provider_config()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = _pkce_verifier()
    db.add(
        OAuthState(
            id=str(uuid.uuid4()),
            state_hash=_hash(state),
            nonce_hash=_hash(nonce),
            nonce_ciphertext=_fernet().encrypt(nonce.encode()).decode(),
            code_verifier=verifier,
            expires_at=_now() + timedelta(minutes=5),
        )
    )
    db.commit()
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    return str(httpx.URL(provider["authorization_endpoint"], params=params))


def _validate_claims(
    token: str, provider: dict[str, Any], nonce: str
) -> dict[str, Any]:
    try:
        jwks_client = jwt.PyJWKClient(provider["jwks_uri"])
        signing_key = jwks_client.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
            audience=settings.oidc_client_id,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "iss", "sub", "aud", "nonce"]},
        )
    except (jwt.PyJWTError, ValueError) as error:
        raise HTTPException(
            status_code=401, detail="Invalid OIDC identity token"
        ) from error
    if not secrets.compare_digest(claims["nonce"], nonce):
        raise HTTPException(status_code=401, detail="OIDC nonce validation failed")
    if claims["exp"] <= int(time.time()):
        raise HTTPException(status_code=401, detail="OIDC token expired")
    return claims


def complete_login(db: Session, code: str, state: str) -> tuple[User, str, str]:
    stored = db.scalar(
        select(OAuthState)
        .where(OAuthState.state_hash == _hash(state))
        .with_for_update()
    )
    if stored is None or stored.used_at is not None:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")
    if _expired(stored.expires_at):
        raise HTTPException(status_code=400, detail="Expired OAuth state")
    provider = _provider_config()
    try:
        response = httpx.post(
            provider["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
                "redirect_uri": settings.oidc_redirect_uri,
                "code_verifier": stored.code_verifier,
            },
            timeout=5,
        )
        response.raise_for_status()
        token_data = response.json()
        id_token = token_data["id_token"]
    except (httpx.HTTPError, KeyError, ValueError) as error:
        raise HTTPException(
            status_code=401, detail="OIDC token exchange failed"
        ) from error
    try:
        nonce = _fernet().decrypt(stored.nonce_ciphertext.encode()).decode()
    except InvalidToken as error:
        raise HTTPException(
            status_code=401, detail="Invalid OIDC nonce state"
        ) from error
    claims = _validate_claims(id_token, provider, nonce)
    stored.used_at = _now()
    identity = db.scalar(
        select(Identity).where(
            Identity.issuer == settings.oidc_issuer,
            Identity.subject == claims["sub"],
        )
    )
    if identity:
        user = db.get(User, identity.user_id)
    else:
        email = claims.get("email") or f"{claims['sub']}@{settings.oidc_issuer}"
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(
                id=str(uuid.uuid4()),
                email=email,
                display_name=claims.get("name") or email,
                is_active=True,
                created_at=_now(),
            )
            db.add(user)
            db.flush()
        db.add(
            Identity(
                id=str(uuid.uuid4()),
                user_id=user.id,
                issuer=settings.oidc_issuer,
                subject=claims["sub"],
                created_at=_now(),
            )
        )
    if user is None or not user.is_active:
        raise HTTPException(status_code=403, detail="User is inactive")
    db.commit()
    return user, issue_access_token(user.id), issue_refresh_token(db, user.id)


def issue_access_token(user_id: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": user_id,
            "iat": now,
            "exp": now + timedelta(minutes=settings.access_token_minutes),
            "iss": "forensicgraph",
            "aud": "forensicgraph-api",
            "typ": "access",
        },
        settings.app_secret_key,
        algorithm="HS256",
    )


def issue_refresh_token(db: Session, user_id: str) -> str:
    raw = secrets.token_urlsafe(48)
    db.add(
        RefreshSession(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash=_hash(raw),
            expires_at=_now() + timedelta(days=settings.refresh_token_days),
            created_at=_now(),
        )
    )
    db.commit()
    return raw


def rotate_refresh_token(db: Session, raw: str) -> tuple[str, str]:
    session = db.scalar(
        select(RefreshSession)
        .where(RefreshSession.token_hash == _hash(raw))
        .with_for_update()
    )
    if (
        session is None
        or session.revoked_at is not None
        or _expired(session.expires_at)
        or session.replaced_by is not None
    ):
        raise HTTPException(status_code=401, detail="Invalid refresh session")
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid refresh session")
    session.revoked_at = _now()
    replacement_id = str(uuid.uuid4())
    session.replaced_by = replacement_id
    replacement = secrets.token_urlsafe(48)
    db.add(
        RefreshSession(
            id=replacement_id,
            user_id=user.id,
            token_hash=_hash(replacement),
            expires_at=_now() + timedelta(days=settings.refresh_token_days),
            created_at=_now(),
        )
    )
    db.commit()
    return issue_access_token(user.id), replacement


def revoke_refresh_token(db: Session, raw: str) -> None:
    session = db.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == _hash(raw))
    )
    if session and session.revoked_at is None:
        session.revoked_at = _now()
        db.commit()
