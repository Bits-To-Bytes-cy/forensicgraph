"""Case management API schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

CASE_ROLES = ("case_lead", "investigator", "reviewer", "observer")
CASE_STATUSES = (
    "draft",
    "open",
    "under_investigation",
    "pending_review",
    "closed",
    "archived",
)


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(default="", max_length=20_000)
    scope: str = Field(default="", max_length=20_000)
    priority: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")


class CasePatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    description: str | None = Field(default=None, max_length=20_000)
    scope: str | None = Field(default=None, max_length=20_000)
    priority: str | None = Field(default=None, pattern=r"^(low|medium|high|critical)$")


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    case_number: int
    title: str
    description: str
    scope: str
    priority: str
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    archived_at: datetime | None


class CaseMemberCreate(BaseModel):
    user_id: str
    role: str = Field(pattern=r"^(case_lead|investigator|reviewer|observer)$")


class CaseMemberResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    role: str
    created_at: datetime


class CaseStatusChange(BaseModel):
    status: str = Field(
        pattern=r"^(draft|open|under_investigation|pending_review|closed|archived)$"
    )


class CaseStatusHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    from_status: str | None
    to_status: str
    changed_by: str
    created_at: datetime
