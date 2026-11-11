"""Shared request dependencies for authentication and tenant authorization."""

from __future__ import annotations

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicgraph.config import settings
from forensicgraph.db import get_db
from forensicgraph.models.auth import Membership, Organization, User

bearer = HTTPBearer(auto_error=False)


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.app_secret_key,
            algorithms=["HS256"],
            audience="forensicgraph-api",
            issuer="forensicgraph",
            options={"require": ["sub", "exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as error:
        raise HTTPException(status_code=401, detail="Invalid access token") from error
    user = db.get(User, claims["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User is inactive or missing")
    return user


def organization_membership(
    organization_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> tuple[Organization, Membership, User]:
    organization = db.get(Organization, organization_id)
    membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == user.id,
        )
    )
    if organization is None or membership is None:
        raise HTTPException(status_code=404, detail="Organization was not found")
    return organization, membership, user


def require_admin(
    context: tuple[Organization, Membership, User] = Depends(organization_membership),
) -> tuple[Organization, Membership, User]:
    if context[1].role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Organization admin role required")
    return context
