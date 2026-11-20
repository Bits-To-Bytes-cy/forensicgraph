"""Authorized, bounded evidence ingestion processing services."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterator

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensicgraph.models.auth import Membership, User
from forensicgraph.models.evidence import EvidenceItem
from forensicgraph.models.processing import ProcessingError, ProcessingRun, RawRecord
from forensicgraph.parsers import ParserError, get_parser
from forensicgraph.services.cases import get_case_context, now
from forensicgraph.storage import get_storage

INGEST_ROLES = {"case_lead", "investigator"}
RUN_STATUSES = {"created", "running", "completed", "failed", "interrupted"}


def _authorized_evidence(
    db: Session, evidence_id: str, user: User
) -> tuple[EvidenceItem, Membership]:
    evidence = db.get(EvidenceItem, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence was not found")
    case, org_membership, case_membership = get_case_context(db, evidence.case_id, user)
    if org_membership.role not in {"owner", "admin"} and (
        case_membership is None or case_membership.role not in INGEST_ROLES
    ):
        raise HTTPException(
            status_code=403, detail="Evidence ingestion permission required"
        )
    if case.organization_id != evidence.organization_id:
        raise HTTPException(status_code=404, detail="Evidence was not found")
    return evidence, org_membership


def _source_chunks(evidence: EvidenceItem) -> Iterator[bytes]:
    yield from get_storage().read(evidence.storage_key)


def _next_attempt(
    db: Session, evidence: EvidenceItem, parser_name: str, parser_version: str
) -> int:
    return (
        db.scalar(
            select(func.max(ProcessingRun.attempt)).where(
                ProcessingRun.evidence_id == evidence.id,
                ProcessingRun.parser_name == parser_name,
                ProcessingRun.parser_version == parser_version,
            )
        )
        or 0
    ) + 1


def _record_error(
    db: Session,
    run: ProcessingRun,
    error_type: str,
    message: str,
    locator: str | None = None,
    details: dict[str, object] | None = None,
) -> None:
    db.add(
        ProcessingError(
            id=str(uuid.uuid4()),
            processing_run_id=run.id,
            evidence_id=run.evidence_id,
            case_id=run.case_id,
            organization_id=run.organization_id,
            source_locator=locator,
            error_type=error_type,
            message=message,
            details=json.dumps(details or {}, sort_keys=True),
            created_at=now(),
        )
    )


def ingest(
    db: Session,
    evidence_id: str,
    user: User,
    parser_name: str,
    batch_size: int,
    reprocess: bool = False,
) -> ProcessingRun:
    evidence, _ = _authorized_evidence(db, evidence_id, user)
    try:
        parser = get_parser(parser_name)
        parser.validate(evidence.media_type, evidence.original_filename)
    except ParserError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if hasattr(parser, "set_format"):
        parser.set_format(evidence.original_filename)

    source_sha256 = evidence.sha256
    existing = db.scalar(
        select(ProcessingRun)
        .where(
            ProcessingRun.evidence_id == evidence.id,
            ProcessingRun.parser_name == parser.name,
            ProcessingRun.parser_version == parser.version,
            ProcessingRun.source_sha256 == source_sha256,
            ProcessingRun.status == "completed",
        )
        .order_by(ProcessingRun.attempt.desc())
    )
    if existing is not None and not reprocess:
        return existing
    timestamp = now()
    run = ProcessingRun(
        id=str(uuid.uuid4()),
        evidence_id=evidence.id,
        case_id=evidence.case_id,
        organization_id=evidence.organization_id,
        requested_by=user.id,
        parser_name=parser.name,
        parser_version=parser.version,
        source_sha256=source_sha256,
        status="created",
        batch_size=batch_size,
        attempt=_next_attempt(db, evidence, parser.name, parser.version),
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    _run_parser(db, run, evidence, parser)
    db.refresh(run)
    return run


def _run_parser(
    db: Session, run: ProcessingRun, evidence: EvidenceItem, parser
) -> None:
    run.status = "running"
    run.started_at = now()
    run.updated_at = run.started_at
    db.commit()
    records_in_batch = 0
    record_number = 0
    try:
        for parsed in parser.parse(_source_chunks(evidence)):
            record_number += 1
            db.add(
                RawRecord(
                    id=str(uuid.uuid4()),
                    processing_run_id=run.id,
                    evidence_id=evidence.id,
                    case_id=evidence.case_id,
                    organization_id=evidence.organization_id,
                    parser_name=run.parser_name,
                    parser_version=run.parser_version,
                    record_number=record_number,
                    source_locator=parsed.source_locator,
                    raw_payload=parsed.raw_payload,
                    raw_sha256=hashlib.sha256(parsed.raw_payload.encode()).hexdigest(),
                    created_at=now(),
                )
            )
            records_in_batch += 1
            run.processed_records = record_number
            run.next_locator = parsed.source_locator
            if records_in_batch >= run.batch_size:
                db.commit()
                records_in_batch = 0
        run.total_records = record_number
        run.status = "completed"
        run.finished_at = now()
        run.updated_at = run.finished_at
        db.commit()
    except ParserError as error:
        if records_in_batch:
            db.commit()
        run.status = "failed"
        run.failed_records = 1
        run.error_summary = str(error)
        run.finished_at = now()
        run.updated_at = run.finished_at
        _record_error(
            db,
            run,
            error.error_type,
            str(error),
            error.locator,
        )
        db.commit()
    except Exception as error:
        db.rollback()
        run = db.get(ProcessingRun, run.id)
        run.status = "interrupted"
        run.error_summary = f"Processing interrupted: {type(error).__name__}: {error}"
        run.finished_at = now()
        run.updated_at = run.finished_at
        _record_error(
            db,
            run,
            "processing_interrupted",
            "Processing interrupted by an unexpected failure",
            run.next_locator,
            {"exception": type(error).__name__},
        )
        db.commit()


def get_run(db: Session, run_id: str, user: User) -> ProcessingRun:
    run = db.get(ProcessingRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Processing run was not found")
    _authorized_evidence(db, run.evidence_id, user)
    return run


def list_errors(db: Session, run_id: str, user: User) -> list[ProcessingError]:
    run = get_run(db, run_id, user)
    return list(
        db.scalars(
            select(ProcessingError)
            .where(ProcessingError.processing_run_id == run.id)
            .order_by(ProcessingError.created_at)
        )
    )


def list_case_runs(db: Session, case_id: str, user: User) -> list[ProcessingRun]:
    get_case_context(db, case_id, user)
    return list(
        db.scalars(
            select(ProcessingRun)
            .where(ProcessingRun.case_id == case_id)
            .order_by(ProcessingRun.created_at.desc())
        )
    )
