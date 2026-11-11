"""Case management HTTP routes."""

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from forensicgraph.api.dependencies import (
    current_user,
    organization_membership,
)
from forensicgraph.db import get_db
from forensicgraph.models.auth import User
from forensicgraph.models.cases import Case, CaseMembership, CaseStatusHistory
from forensicgraph.schemas.cases import (
    CaseCreate,
    CaseMemberCreate,
    CaseMemberResponse,
    CasePatch,
    CaseResponse,
    CaseStatusChange,
    CaseStatusHistoryResponse,
)
from forensicgraph.services.cases import (
    assign_member,
    can_manage_case,
    change_status,
    create_case,
    get_case_context,
    remove_member,
    update_case,
)

router = APIRouter(tags=["cases"])


@router.post(
    "/organizations/{organization_id}/cases",
    response_model=CaseResponse,
    status_code=201,
)
def create(
    organization_id: str,
    payload: CaseCreate,
    context=Depends(organization_membership),
    db: Session = Depends(get_db),
) -> Case:
    if context[1].role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Organization admin role required")
    return create_case(db, organization_id, context[2], payload.model_dump())


@router.get(
    "/organizations/{organization_id}/cases",
    response_model=list[CaseResponse],
)
def list_cases(
    organization_id: str,
    context=Depends(organization_membership),
    db: Session = Depends(get_db),
) -> list[Case]:
    return list(
        db.scalars(
            select(Case)
            .join(
                CaseMembership,
                (CaseMembership.case_id == Case.id)
                & (CaseMembership.organization_id == organization_id),
            )
            .where(
                Case.organization_id == organization_id,
            )
            .where(
                (context[1].role.in_(("owner", "admin")))
                | (CaseMembership.user_id == context[2].id)
            )
            .distinct()
            .order_by(Case.case_number)
        )
    )


@router.get(
    "/organizations/{organization_id}/cases/{case_id}",
    response_model=CaseResponse,
)
def get_case(
    organization_id: str,
    case_id: str,
    context=Depends(organization_membership),
    db: Session = Depends(get_db),
) -> Case:
    case, _, _ = get_case_context(db, case_id, context[2])
    if case.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Case was not found")
    return case


@router.get("/cases/{case_id}", response_model=CaseResponse)
def get_case_by_id(
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Case:
    case, _, _ = get_case_context(db, case_id, user)
    return case


@router.patch("/cases/{case_id}", response_model=CaseResponse)
def patch_case(
    case_id: str,
    payload: CasePatch,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Case:
    case, org_membership, case_membership = get_case_context(db, case_id, user)
    if not can_manage_case(org_membership, case_membership):
        raise HTTPException(
            status_code=403, detail="Case management permission required"
        )
    return update_case(db, case, user, payload.model_dump(exclude_unset=True))


@router.post(
    "/cases/{case_id}/members", response_model=CaseMemberResponse, status_code=201
)
def add_case_member(
    case_id: str,
    payload: CaseMemberCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> CaseMemberResponse:
    case, org_membership, _ = get_case_context(db, case_id, user)
    assignment = assign_member(db, case, user, org_membership, payload.model_dump())
    target = db.get(User, assignment.user_id)
    return CaseMemberResponse(
        user_id=target.id,
        email=target.email,
        display_name=target.display_name,
        role=assignment.role,
        created_at=assignment.created_at,
    )


@router.get("/cases/{case_id}/members", response_model=list[CaseMemberResponse])
def list_case_members(
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[CaseMemberResponse]:
    case, _, _ = get_case_context(db, case_id, user)
    rows = db.execute(
        select(CaseMembership, User)
        .join(User, User.id == CaseMembership.user_id)
        .where(CaseMembership.case_id == case.id)
        .order_by(User.email)
    )
    return [
        CaseMemberResponse(
            user_id=member.user_id,
            email=target.email,
            display_name=target.display_name,
            role=member.role,
            created_at=member.created_at,
        )
        for member, target in rows
    ]


@router.delete("/cases/{case_id}/members/{user_id}", status_code=204)
def delete_case_member(
    case_id: str,
    user_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    case, _, _ = get_case_context(db, case_id, user)
    remove_member(db, case, user, user_id)
    return Response(status_code=204)


@router.post("/cases/{case_id}/status", response_model=CaseResponse)
def set_case_status(
    case_id: str,
    payload: CaseStatusChange,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Case:
    case, _, _ = get_case_context(db, case_id, user)
    return change_status(db, case, user, payload.status)


@router.get(
    "/cases/{case_id}/history",
    response_model=list[CaseStatusHistoryResponse],
)
def case_history(
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[CaseStatusHistory]:
    case, _, _ = get_case_context(db, case_id, user)
    return list(
        db.scalars(
            select(CaseStatusHistory)
            .where(CaseStatusHistory.case_id == case.id)
            .order_by(CaseStatusHistory.created_at)
        )
    )
