"""Organization and membership routes with strict tenant checks."""

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicgraph.api.dependencies import (
    current_user,
    organization_membership,
    require_admin,
)
from forensicgraph.db import get_db
from forensicgraph.models.auth import Membership, Organization, User
from forensicgraph.schemas.auth import (
    MemberCreate,
    MemberResponse,
    OrganizationCreate,
    OrganizationResponse,
)

router = APIRouter(prefix="/organizations", tags=["organizations"])


@router.post("", response_model=OrganizationResponse, status_code=201)
def create_organization(
    payload: OrganizationCreate,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> Organization:
    if db.scalar(select(Organization).where(Organization.slug == payload.slug)):
        raise HTTPException(status_code=409, detail="Organization slug already exists")
    organization = Organization(
        id=str(uuid.uuid4()),
        name=payload.name,
        slug=payload.slug,
        created_at=datetime.now(UTC),
    )
    db.add(organization)
    db.flush()
    db.add(
        Membership(
            id=str(uuid.uuid4()),
            organization_id=organization.id,
            user_id=user.id,
            role="owner",
            created_at=datetime.now(UTC),
        )
    )
    db.commit()
    db.refresh(organization)
    return organization


@router.get("", response_model=list[OrganizationResponse])
def list_organizations(
    db: Session = Depends(get_db), user: User = Depends(current_user)
) -> list[Organization]:
    return list(
        db.scalars(
            select(Organization)
            .join(Membership)
            .where(Membership.user_id == user.id)
            .order_by(Organization.created_at)
        )
    )


@router.get("/{organization_id}", response_model=OrganizationResponse)
def get_organization(
    context=Depends(organization_membership),
) -> Organization:
    return context[0]


@router.post(
    "/{organization_id}/members", response_model=MemberResponse, status_code=201
)
def add_member(
    organization_id: str,
    payload: MemberCreate,
    context=Depends(require_admin),
    db: Session = Depends(get_db),
) -> MemberResponse:
    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None:
        raise HTTPException(status_code=404, detail="User was not found")
    existing = db.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == user.id,
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="User is already a member")
    membership = Membership(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        user_id=user.id,
        role=payload.role,
        created_at=datetime.now(UTC),
    )
    db.add(membership)
    db.commit()
    return MemberResponse(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=membership.role,
    )


@router.get("/{organization_id}/members", response_model=list[MemberResponse])
def list_members(
    context=Depends(organization_membership),
    db: Session = Depends(get_db),
) -> list[MemberResponse]:
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == context[0].id)
        .order_by(User.email)
    )
    return [
        MemberResponse(
            user_id=user.id,
            email=user.email,
            display_name=user.display_name,
            role=membership.role,
        )
        for membership, user in rows
    ]
