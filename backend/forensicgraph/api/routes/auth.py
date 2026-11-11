"""OIDC authentication routes."""

from fastapi import APIRouter, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from forensicgraph.api.dependencies import current_user
from forensicgraph.config import settings
from forensicgraph.db import get_db
from forensicgraph.schemas.auth import (
    LogoutRequest,
    RefreshRequest,
    TokenResponse,
    UserResponse,
)
from forensicgraph.services.auth import (
    begin_login,
    complete_login,
    revoke_refresh_token,
    rotate_refresh_token,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.api_route("/login", methods=["GET", "POST"])
def login(db: Session = Depends(get_db)) -> RedirectResponse:
    return RedirectResponse(begin_login(db), status_code=307)


@router.get("/callback", response_model=TokenResponse)
def callback(code: str, state: str, db: Session = Depends(get_db)) -> TokenResponse:
    user, access_token, refresh_token = complete_login(db, code, state)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_minutes * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    access_token, refresh_token = rotate_refresh_token(db, payload.refresh_token)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_minutes * 60,
    )


@router.post("/logout", status_code=204)
def logout(payload: LogoutRequest, db: Session = Depends(get_db)) -> None:
    revoke_refresh_token(db, payload.refresh_token)


@router.get("/me", response_model=UserResponse)
def me(user=Depends(current_user)) -> UserResponse:
    return UserResponse.model_validate(user)
