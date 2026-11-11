"""API schemas for authentication and organization management."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: str


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9-]*$")


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    slug: str
    created_at: datetime


class MemberCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = Field(default="member", pattern=r"^(member|admin|owner)$")


class MemberResponse(BaseModel):
    user_id: str
    email: str
    display_name: str
    role: str


class LogoutRequest(BaseModel):
    refresh_token: str = Field(min_length=20)


class RefreshRequest(LogoutRequest):
    pass
