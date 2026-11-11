"""Evidence Vault HTTP routes."""

from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from forensicgraph.api.dependencies import current_user
from forensicgraph.db import get_db
from forensicgraph.models.auth import User
from forensicgraph.schemas.evidence import (
    CustodyEventResponse,
    EvidenceDerivativeResponse,
    EvidenceResponse,
    EvidenceUploadCreate,
    EvidenceUploadResponse,
    IntegrityCheckResponse,
)
from forensicgraph.services.evidence import (
    complete_upload,
    create_derivative,
    create_upload,
    custody,
    derivatives,
    download,
    get_evidence,
    list_evidence,
    receive_upload,
    verify_evidence,
)

router = APIRouter(tags=["evidence"])


@router.post(
    "/cases/{case_id}/evidence/uploads",
    response_model=EvidenceUploadResponse,
    status_code=201,
)
def start_upload(
    case_id: str,
    payload: EvidenceUploadCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return create_upload(
        db,
        case_id,
        user,
        payload.original_filename,
        payload.media_type,
        payload.expected_size,
    )


@router.put(
    "/evidence/uploads/{upload_id}/content",
    response_model=EvidenceUploadResponse,
)
def upload_content(
    upload_id: str,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return receive_upload(db, upload_id, user, file)


@router.post(
    "/evidence/uploads/{upload_id}/complete",
    response_model=EvidenceResponse,
)
def finish_upload(
    upload_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return complete_upload(db, upload_id, user)


@router.get(
    "/cases/{case_id}/evidence",
    response_model=list[EvidenceResponse],
)
def evidence_inventory(
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return list_evidence(db, case_id, user)


@router.get("/evidence/{evidence_id}", response_model=EvidenceResponse)
def evidence_detail(
    evidence_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return get_evidence(db, evidence_id, user)


@router.post(
    "/evidence/{evidence_id}/verify",
    response_model=IntegrityCheckResponse,
)
def verify(
    evidence_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return verify_evidence(db, evidence_id, user)


@router.get(
    "/evidence/{evidence_id}/custody",
    response_model=list[CustodyEventResponse],
)
def custody_history(
    evidence_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return custody(db, evidence_id, user)


@router.get("/evidence/{evidence_id}/download")
def download_original(
    evidence_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    evidence, stream = download(db, evidence_id, user)
    return StreamingResponse(
        stream,
        media_type=evidence.media_type,
        headers={
            "Content-Disposition": (
                f'attachment; filename="{evidence.original_filename}"'
            ),
            "Content-Length": str(evidence.size_bytes),
        },
    )


@router.post(
    "/evidence/{evidence_id}/derivatives",
    response_model=EvidenceDerivativeResponse,
    status_code=201,
)
def register_derivative(
    evidence_id: str,
    file: UploadFile = File(...),
    purpose: str = Form(..., min_length=1, max_length=500),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return create_derivative(db, evidence_id, user, file, purpose)


@router.get(
    "/evidence/{evidence_id}/derivatives",
    response_model=list[EvidenceDerivativeResponse],
)
def list_derivatives(
    evidence_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return derivatives(db, evidence_id, user)
