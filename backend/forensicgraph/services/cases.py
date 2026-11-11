"""Case management business rules and transaction boundaries."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensicgraph.models.auth import Membership, Organization, User
from forensicgraph.models.cases import (
    Case,
    CaseMembership,
    CaseStatusHistory,
    SystemAuditEvent,
)

ROLE_ORDER = {"observer": 1, "investigator": 2, "reviewer": 2, "case_lead": 3}
TRANSITIONS = {
    "draft": {"open", "archived"},
    "open": {"under_investigation", "archived"},
    "under_investigation": {"pending_review", "open", "archived"},
    "pending_review": {"closed", "under_investigation"},
    "closed": {"archived"},
    "archived": set(),
}


def now() -> datetime:
    return datetime.now(UTC)


def add_audit(
    db: Session,
    organization_id: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, object] | None = None,
) -> None:
    db.add(
        SystemAuditEvent(
            id=str(uuid.uuid4()),
            organization_id=organization_id,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=json.dumps(details or {}, sort_keys=True),
            created_at=now(),
        )
    )


def get_case_context(
    db: Session, case_id: str, user: User, *, for_update: bool = False
) -> tuple[Case, Membership, CaseMembership | None]:
    statement = select(Case).where(Case.id == case_id)
    if for_update:
        statement = statement.with_for_update()
    case = db.scalar(statement)
    if case is None:
        raise HTTPException(status_code=404, detail="Case was not found")
    org_membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == case.organization_id,
            Membership.user_id == user.id,
        )
    )
    case_membership = db.scalar(
        select(CaseMembership).where(
            CaseMembership.case_id == case.id,
            CaseMembership.user_id == user.id,
        )
    )
    if org_membership is None or (
        case_membership is None and org_membership.role not in {"owner", "admin"}
    ):
        raise HTTPException(status_code=404, detail="Case was not found")
    return case, org_membership, case_membership


def can_manage_case(
    org_membership: Membership, case_membership: CaseMembership | None
) -> bool:
    return org_membership.role in {"owner", "admin"} or (
        case_membership is not None and case_membership.role == "case_lead"
    )


def create_case(
    db: Session, organization_id: str, creator: User, data: dict[str, str]
) -> Case:
    organization = db.scalar(
        select(Organization).where(Organization.id == organization_id).with_for_update()
    )
    creator_org = db.scalar(
        select(Membership).where(
            Membership.organization_id == organization_id,
            Membership.user_id == creator.id,
        )
    )
    if (
        organization is None
        or creator_org is None
        or creator_org.role not in {"owner", "admin"}
    ):
        raise HTTPException(status_code=403, detail="Organization admin role required")
    last_number = db.scalar(
        select(func.max(Case.case_number)).where(
            Case.organization_id == organization_id
        )
    )
    timestamp = now()
    case = Case(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        case_number=(last_number or 0) + 1,
        created_by=creator.id,
        created_at=timestamp,
        updated_at=timestamp,
        **data,
    )
    db.add(case)
    db.flush()
    db.add(
        CaseMembership(
            id=str(uuid.uuid4()),
            case_id=case.id,
            organization_id=organization_id,
            user_id=creator.id,
            role="case_lead",
            assigned_by=creator.id,
            created_at=timestamp,
        )
    )
    db.add(
        CaseStatusHistory(
            id=str(uuid.uuid4()),
            case_id=case.id,
            organization_id=organization_id,
            from_status=None,
            to_status=case.status,
            changed_by=creator.id,
            created_at=timestamp,
        )
    )
    add_audit(
        db,
        organization_id,
        creator.id,
        "case.created",
        "case",
        case.id,
        {"case_number": case.case_number},
    )
    db.commit()
    db.refresh(case)
    return case


def update_case(db: Session, case: Case, actor: User, data: dict[str, object]) -> Case:
    if case.status == "archived":
        raise HTTPException(status_code=409, detail="Archived cases are immutable")
    for key, value in data.items():
        if value is not None:
            setattr(case, key, value)
    case.updated_at = now()
    add_audit(db, case.organization_id, actor.id, "case.updated", "case", case.id, data)
    db.commit()
    db.refresh(case)
    return case


def assign_member(
    db: Session,
    case: Case,
    actor: User,
    actor_org: Membership,
    payload: dict[str, str],
) -> CaseMembership:
    actor_case = db.scalar(
        select(CaseMembership).where(
            CaseMembership.case_id == case.id, CaseMembership.user_id == actor.id
        )
    )
    if not can_manage_case(actor_org, actor_case):
        raise HTTPException(
            status_code=403, detail="Case management permission required"
        )
    if payload["role"] == "case_lead" and actor_org.role not in {"owner", "admin"}:
        raise HTTPException(
            status_code=403, detail="Only organization admins may assign leads"
        )
    target_org = db.scalar(
        select(Membership)
        .where(
            Membership.organization_id == case.organization_id,
            Membership.user_id == payload["user_id"],
        )
        .join(User, User.id == Membership.user_id)
        .where(User.is_active.is_(True))
    )
    if target_org is None:
        raise HTTPException(
            status_code=400, detail="User is not an active organization member"
        )
    if db.scalar(
        select(CaseMembership).where(
            CaseMembership.case_id == case.id,
            CaseMembership.user_id == payload["user_id"],
        )
    ):
        raise HTTPException(status_code=409, detail="User is already assigned")
    assignment = CaseMembership(
        id=str(uuid.uuid4()),
        case_id=case.id,
        organization_id=case.organization_id,
        user_id=payload["user_id"],
        role=payload["role"],
        assigned_by=actor.id,
        created_at=now(),
    )
    db.add(assignment)
    add_audit(
        db,
        case.organization_id,
        actor.id,
        "case.member_assigned",
        "case_membership",
        assignment.id,
        payload,
    )
    db.commit()
    return assignment


def remove_member(db: Session, case: Case, actor: User, user_id: str) -> None:
    case_membership = db.scalar(
        select(CaseMembership)
        .where(CaseMembership.case_id == case.id, CaseMembership.user_id == user_id)
        .with_for_update()
    )
    actor_membership = db.scalar(
        select(CaseMembership).where(
            CaseMembership.case_id == case.id, CaseMembership.user_id == actor.id
        )
    )
    actor_org = db.scalar(
        select(Membership).where(
            Membership.organization_id == case.organization_id,
            Membership.user_id == actor.id,
        )
    )
    if not case_membership:
        raise HTTPException(status_code=404, detail="Case member was not found")
    if not actor_org or not can_manage_case(actor_org, actor_membership):
        raise HTTPException(
            status_code=403, detail="Case management permission required"
        )
    if case_membership.role == "case_lead":
        lead_count = db.scalar(
            select(func.count())
            .select_from(CaseMembership)
            .where(
                CaseMembership.case_id == case.id,
                CaseMembership.role == "case_lead",
            )
        )
        if lead_count <= 1:
            raise HTTPException(
                status_code=409, detail="Cannot remove the last Case Lead"
            )
    db.delete(case_membership)
    add_audit(
        db,
        case.organization_id,
        actor.id,
        "case.member_removed",
        "case_membership",
        case_membership.id,
        {"user_id": user_id},
    )
    db.commit()


def change_status(db: Session, case: Case, actor: User, new_status: str) -> Case:
    context = get_case_context(db, case.id, actor, for_update=True)
    if not can_manage_case(context[1], context[2]):
        raise HTTPException(
            status_code=403, detail="Case management permission required"
        )
    if new_status not in TRANSITIONS[case.status]:
        raise HTTPException(
            status_code=409,
            detail=f"Invalid case status transition: {case.status} -> {new_status}",
        )
    timestamp = now()
    previous = case.status
    case.status = new_status
    case.updated_at = timestamp
    if new_status == "closed":
        case.closed_at = timestamp
    if new_status == "archived":
        case.archived_at = timestamp
    db.add(
        CaseStatusHistory(
            id=str(uuid.uuid4()),
            case_id=case.id,
            organization_id=case.organization_id,
            from_status=previous,
            to_status=new_status,
            changed_by=actor.id,
            created_at=timestamp,
        )
    )
    add_audit(
        db,
        case.organization_id,
        actor.id,
        "case.status_changed",
        "case",
        case.id,
        {"from": previous, "to": new_status},
    )
    db.commit()
    db.refresh(case)
    return case
