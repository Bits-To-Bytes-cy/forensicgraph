"""Evidence ingestion processing routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from forensicgraph.api.dependencies import current_user
from forensicgraph.db import get_db
from forensicgraph.models.auth import User
from forensicgraph.schemas.processing import (
    IngestRequest,
    ProcessingErrorResponse,
    ProcessingRunResponse,
)
from forensicgraph.services.processing import (
    get_run,
    ingest,
    list_case_runs,
    list_errors,
)

router = APIRouter(tags=["processing"])


@router.post(
    "/evidence/{evidence_id}/ingest",
    response_model=ProcessingRunResponse,
    status_code=201,
)
def ingest_evidence(
    evidence_id: str,
    payload: IngestRequest,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return ingest(
        db,
        evidence_id,
        user,
        payload.parser_name,
        payload.batch_size,
        payload.reprocess,
    )


@router.get(
    "/processing-runs/{run_id}",
    response_model=ProcessingRunResponse,
)
def processing_run(
    run_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return get_run(db, run_id, user)


@router.get(
    "/processing-runs/{run_id}/errors",
    response_model=list[ProcessingErrorResponse],
)
def processing_run_errors(
    run_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return list_errors(db, run_id, user)


@router.get(
    "/cases/{case_id}/processing-runs",
    response_model=list[ProcessingRunResponse],
)
def case_processing_runs(
    case_id: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return list_case_runs(db, case_id, user)
