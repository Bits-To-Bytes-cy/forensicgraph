"""Evidence Vault, storage verification, and append-only TrustLedger services."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Iterator
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from forensicgraph.config import settings
from forensicgraph.models.auth import Membership, User
from forensicgraph.models.cases import Case, CaseMembership
from forensicgraph.models.evidence import (
    EvidenceCustodyEvent,
    EvidenceDerivative,
    EvidenceIntegrityCheck,
    EvidenceItem,
    EvidenceUploadSession,
)
from forensicgraph.services.cases import (
    add_audit,
    get_case_context,
    now,
)
from forensicgraph.storage import ObjectStorage, get_storage

SAFE_FILENAME = re.compile(r"^[^/\\\x00]+$")
UPLOAD_ROLES = {"case_lead", "investigator"}
VERIFY_ROLES = {"case_lead", "investigator", "reviewer"}


def _allowed_media_types() -> set[str]:
    return {
        value.strip()
        for value in settings.evidence_allowed_media_types.split(",")
        if value.strip()
    }


def _validate_filename(filename: str) -> str:
    if not SAFE_FILENAME.fullmatch(filename) or filename in {".", ".."}:
        raise HTTPException(status_code=400, detail="Unsafe evidence filename")
    return filename


def _validate_media_type(media_type: str) -> None:
    if media_type not in _allowed_media_types():
        raise HTTPException(
            status_code=415, detail="Evidence media type is not allowed"
        )


def _validate_content_signature(media_type: str, prefix: bytes) -> None:
    signatures = {
        "application/pdf": b"%PDF-",
        "application/zip": b"PK\x03\x04",
        "image/png": b"\x89PNG\r\n\x1a\n",
    }
    signature = signatures.get(media_type)
    if signature and not prefix.startswith(signature):
        raise HTTPException(
            status_code=415,
            detail="Evidence content does not match the declared media type",
        )
    if media_type == "image/jpeg" and not prefix.startswith(b"\xff\xd8\xff"):
        raise HTTPException(
            status_code=415,
            detail="Evidence content does not match the declared media type",
        )


def _case_access(
    db: Session, case_id: str, user: User
) -> tuple[Case, Membership, CaseMembership | None]:
    return get_case_context(db, case_id, user)


def _require_role(
    db: Session,
    case_id: str,
    user: User,
    allowed_roles: set[str],
) -> tuple[Case, Membership, CaseMembership | None]:
    case, org_membership, case_membership = _case_access(db, case_id, user)
    if org_membership.role in {"owner", "admin"}:
        return case, org_membership, case_membership
    if case_membership is None or case_membership.role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Evidence permission required")
    return case, org_membership, case_membership


def _hash_stream(chunks: Iterator[bytes]) -> tuple[int, str, str]:
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    size = 0
    for chunk in chunks:
        size += len(chunk)
        if size > settings.evidence_max_upload_bytes:
            raise HTTPException(status_code=413, detail="Evidence file is too large")
        sha256.update(chunk)
        sha512.update(chunk)
    return size, sha256.hexdigest(), sha512.hexdigest()


def _hash_storage(storage: ObjectStorage, key: str) -> tuple[int, str, str]:
    return _hash_stream(storage.read(key))


def create_upload(
    db: Session,
    case_id: str,
    user: User,
    filename: str,
    media_type: str,
    expected_size: int | None,
) -> EvidenceUploadSession:
    case, _, _ = _require_role(db, case_id, user, UPLOAD_ROLES)
    filename = _validate_filename(filename)
    _validate_media_type(media_type)
    if expected_size is not None and expected_size > settings.evidence_max_upload_bytes:
        raise HTTPException(status_code=413, detail="Evidence file is too large")
    timestamp = now()
    session = EvidenceUploadSession(
        id=str(uuid.uuid4()),
        case_id=case.id,
        organization_id=case.organization_id,
        created_by=user.id,
        original_filename=filename,
        media_type=media_type,
        expected_size=expected_size,
        quarantine_key=f"quarantine/{case.organization_id}/{case.id}/{uuid.uuid4()}",
        status="created",
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def _upload_file_to_quarantine(
    upload: UploadFile,
    storage: ObjectStorage,
    key: str,
    media_type: str,
) -> tuple[int, str, str]:
    with NamedTemporaryFile(prefix="forensicgraph-upload-", suffix=".bin") as temporary:
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        size = 0
        prefix = b""
        while chunk := upload.file.read(1024 * 1024):
            size += len(chunk)
            if size > settings.evidence_max_upload_bytes:
                raise HTTPException(
                    status_code=413, detail="Evidence file is too large"
                )
            sha256.update(chunk)
            sha512.update(chunk)
            if len(prefix) < 16:
                prefix += chunk[: 16 - len(prefix)]
            temporary.write(chunk)
        temporary.flush()
        _validate_content_signature(media_type, prefix)
        storage.put_file(key, Path(temporary.name), media_type)
    return size, sha256.hexdigest(), sha512.hexdigest()


def receive_upload(
    db: Session, upload_id: str, user: User, upload: UploadFile
) -> EvidenceUploadSession:
    session = db.scalar(
        select(EvidenceUploadSession)
        .where(EvidenceUploadSession.id == upload_id)
        .with_for_update()
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session was not found")
    _require_role(db, session.case_id, user, UPLOAD_ROLES)
    if session.created_by != user.id:
        raise HTTPException(status_code=403, detail="Upload session owner required")
    if session.status == "completed":
        raise HTTPException(status_code=409, detail="Upload session is complete")
    storage = get_storage()
    try:
        size, sha256, sha512 = _upload_file_to_quarantine(
            upload, storage, session.quarantine_key, session.media_type
        )
    except HTTPException:
        raise
    except Exception as error:
        session.status = "failed"
        session.error_message = "Object storage upload failed"
        session.updated_at = now()
        db.commit()
        raise HTTPException(
            status_code=503, detail="Evidence storage upload failed"
        ) from error
    if session.expected_size is not None and size != session.expected_size:
        session.status = "failed"
        session.error_message = "Uploaded size did not match expected size"
        session.updated_at = now()
        db.commit()
        raise HTTPException(status_code=400, detail="Uploaded size does not match")
    session.bytes_received = size
    session.uploaded_sha256 = sha256
    session.uploaded_sha512 = sha512
    session.status = "uploaded"
    session.updated_at = now()
    db.commit()
    db.refresh(session)
    return session


def _append_ledger(
    db: Session,
    evidence: EvidenceItem,
    actor_id: str,
    event_type: str,
    payload: dict[str, object],
) -> EvidenceCustodyEvent:
    db.execute(
        select(EvidenceItem).where(EvidenceItem.id == evidence.id).with_for_update()
    )
    previous = db.scalar(
        select(EvidenceCustodyEvent)
        .where(EvidenceCustodyEvent.evidence_id == evidence.id)
        .order_by(EvidenceCustodyEvent.sequence_number.desc())
    )
    sequence = (previous.sequence_number if previous else 0) + 1
    occurred_at = now()
    canonical = json.dumps(
        {
            "actor_id": actor_id,
            "evidence_id": evidence.id,
            "event_type": event_type,
            "occurred_at": occurred_at.isoformat(),
            "payload": payload,
            "previous_hash": previous.event_hash if previous else None,
            "sequence_number": sequence,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    event = EvidenceCustodyEvent(
        id=str(uuid.uuid4()),
        evidence_id=evidence.id,
        organization_id=evidence.organization_id,
        sequence_number=sequence,
        event_type=event_type,
        actor_id=actor_id,
        occurred_at=occurred_at,
        payload=json.dumps(payload, sort_keys=True, separators=(",", ":")),
        previous_hash=previous.event_hash if previous else None,
        event_hash=hashlib.sha256(canonical.encode()).hexdigest(),
    )
    db.add(event)
    return event


def complete_upload(db: Session, upload_id: str, user: User) -> EvidenceItem:
    session = db.scalar(
        select(EvidenceUploadSession)
        .where(EvidenceUploadSession.id == upload_id)
        .with_for_update()
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session was not found")
    case, _, _ = _require_role(db, session.case_id, user, UPLOAD_ROLES)
    if session.created_by != user.id:
        raise HTTPException(status_code=403, detail="Upload session owner required")
    if session.status == "completed" and session.final_evidence_id:
        evidence = db.get(EvidenceItem, session.final_evidence_id)
        if evidence is not None:
            return evidence
    if session.status != "uploaded":
        raise HTTPException(status_code=409, detail="Upload content is not ready")
    storage = get_storage()
    try:
        if not storage.exists(session.quarantine_key):
            raise HTTPException(status_code=409, detail="Quarantine object is missing")
        size, sha256, sha512 = _hash_storage(storage, session.quarantine_key)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=503, detail="Evidence storage read-back failed"
        ) from error
    if (
        size != session.bytes_received
        or sha256 != session.uploaded_sha256
        or sha512 != session.uploaded_sha512
    ):
        session.status = "failed"
        session.error_message = "Quarantine read-back hash mismatch"
        session.updated_at = now()
        db.commit()
        raise HTTPException(
            status_code=409, detail="Evidence read-back verification failed"
        )
    evidence_id = session.final_evidence_id or str(uuid.uuid4())
    final_key = f"evidence/{case.organization_id}/{case.id}/{evidence_id}/original"
    try:
        storage.copy(session.quarantine_key, final_key)
        copied_size, copied_sha256, copied_sha512 = _hash_storage(storage, final_key)
    except Exception as error:
        raise HTTPException(
            status_code=503, detail="Evidence storage finalization failed"
        ) from error
    if (copied_size, copied_sha256, copied_sha512) != (size, sha256, sha512):
        raise HTTPException(
            status_code=409, detail="Evidence finalization verification failed"
        )
    last_number = db.scalar(
        select(func.max(EvidenceItem.evidence_number))
        .where(EvidenceItem.case_id == case.id)
        .with_for_update()
    )
    timestamp = now()
    evidence = EvidenceItem(
        id=evidence_id,
        case_id=case.id,
        organization_id=case.organization_id,
        evidence_number=(last_number or 0) + 1,
        original_filename=session.original_filename,
        media_type=session.media_type,
        size_bytes=size,
        sha256=sha256,
        sha512=sha512,
        storage_key=final_key,
        status="available",
        created_by=session.created_by,
        created_at=timestamp,
        updated_at=timestamp,
    )
    db.add(evidence)
    db.flush()
    _append_ledger(
        db,
        evidence,
        user.id,
        "evidence.created",
        {"sha256": sha256, "sha512": sha512, "size_bytes": size},
    )
    session.final_evidence_id = evidence.id
    session.status = "completed"
    session.updated_at = timestamp
    add_audit(
        db,
        case.organization_id,
        user.id,
        "evidence.created",
        "evidence",
        evidence.id,
        {"evidence_number": evidence.evidence_number},
    )
    db.commit()
    db.refresh(evidence)
    return evidence


def get_evidence(db: Session, evidence_id: str, user: User) -> EvidenceItem:
    evidence = db.get(EvidenceItem, evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence was not found")
    _case_access(db, evidence.case_id, user)
    return evidence


def list_evidence(db: Session, case_id: str, user: User) -> list[EvidenceItem]:
    _case_access(db, case_id, user)
    return list(
        db.scalars(
            select(EvidenceItem)
            .where(EvidenceItem.case_id == case_id)
            .order_by(EvidenceItem.evidence_number)
        )
    )


def verify_evidence(
    db: Session, evidence_id: str, user: User
) -> EvidenceIntegrityCheck:
    evidence = get_evidence(db, evidence_id, user)
    case, org_membership, case_membership = _case_access(db, evidence.case_id, user)
    if org_membership.role not in {"owner", "admin"} and (
        case_membership is None or case_membership.role not in VERIFY_ROLES
    ):
        raise HTTPException(status_code=403, detail="Evidence verification required")
    storage = get_storage()
    try:
        size, sha256, sha512 = _hash_storage(storage, evidence.storage_key)
        storage_readback = True
    except Exception as error:
        size, sha256, sha512 = 0, "", ""
        storage_readback = False
        error_message = str(error)
    else:
        error_message = ""
    events = list(
        db.scalars(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == evidence.id)
            .order_by(EvidenceCustodyEvent.sequence_number)
        )
    )
    chain_valid = _verify_chain(events)
    hashes_match = (
        storage_readback
        and size == evidence.size_bytes
        and sha256 == evidence.sha256
        and sha512 == evidence.sha512
    )
    details = {
        "storage_key": evidence.storage_key,
        "error": error_message,
        "event_count": len(events),
    }
    check = EvidenceIntegrityCheck(
        id=str(uuid.uuid4()),
        evidence_id=evidence.id,
        organization_id=case.organization_id,
        checked_by=user.id,
        sha256=sha256,
        sha512=sha512,
        size_bytes=size,
        storage_readback=storage_readback,
        hashes_match=hashes_match,
        chain_valid=chain_valid,
        details=json.dumps(details, sort_keys=True),
        checked_at=now(),
    )
    db.add(check)
    if hashes_match and chain_valid:
        evidence.verified_at = check.checked_at
    _append_ledger(
        db,
        evidence,
        user.id,
        "evidence.integrity_checked",
        {
            "hashes_match": hashes_match,
            "chain_valid": chain_valid,
            "storage_readback": storage_readback,
        },
    )
    db.commit()
    db.refresh(check)
    return check


def _verify_chain(events: list[EvidenceCustodyEvent]) -> bool:
    previous_hash: str | None = None
    for event in events:
        canonical = json.dumps(
            {
                "actor_id": event.actor_id,
                "evidence_id": event.evidence_id,
                "event_type": event.event_type,
                "occurred_at": event.occurred_at.isoformat(),
                "payload": json.loads(event.payload),
                "previous_hash": previous_hash,
                "sequence_number": event.sequence_number,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        if event.previous_hash != previous_hash:
            return False
        if event.event_hash != hashlib.sha256(canonical.encode()).hexdigest():
            return False
        previous_hash = event.event_hash
    return True


def custody(db: Session, evidence_id: str, user: User) -> list[EvidenceCustodyEvent]:
    evidence = get_evidence(db, evidence_id, user)
    return list(
        db.scalars(
            select(EvidenceCustodyEvent)
            .where(EvidenceCustodyEvent.evidence_id == evidence.id)
            .order_by(EvidenceCustodyEvent.sequence_number)
        )
    )


def download(
    db: Session, evidence_id: str, user: User
) -> tuple[EvidenceItem, Iterator[bytes]]:
    evidence = get_evidence(db, evidence_id, user)
    try:
        return evidence, get_storage().read(evidence.storage_key)
    except Exception as error:
        raise HTTPException(
            status_code=503, detail="Evidence storage unavailable"
        ) from error


def create_derivative(
    db: Session,
    evidence_id: str,
    user: User,
    upload: UploadFile,
    purpose: str,
) -> EvidenceDerivative:
    evidence = get_evidence(db, evidence_id, user)
    _require_role(db, evidence.case_id, user, UPLOAD_ROLES)
    filename = _validate_filename(upload.filename or "derivative.bin")
    media_type = upload.content_type or "application/octet-stream"
    _validate_media_type(media_type)
    derivative_id = str(uuid.uuid4())
    key = f"derivatives/{evidence.organization_id}/{evidence.id}/{derivative_id}"
    storage = get_storage()
    try:
        size, sha256, sha512 = _upload_file_to_quarantine(
            upload, storage, key, media_type
        )
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=503, detail="Derivative upload failed"
        ) from error
    derivative = EvidenceDerivative(
        id=derivative_id,
        evidence_id=evidence.id,
        organization_id=evidence.organization_id,
        created_by=user.id,
        original_filename=filename,
        media_type=media_type,
        purpose=purpose,
        size_bytes=size,
        sha256=sha256,
        sha512=sha512,
        storage_key=key,
        created_at=now(),
    )
    db.add(derivative)
    _append_ledger(
        db,
        evidence,
        user.id,
        "evidence.derivative_registered",
        {"derivative_id": derivative.id, "sha256": sha256},
    )
    db.commit()
    db.refresh(derivative)
    return derivative


def derivatives(db: Session, evidence_id: str, user: User) -> list[EvidenceDerivative]:
    evidence = get_evidence(db, evidence_id, user)
    return list(
        db.scalars(
            select(EvidenceDerivative)
            .where(EvidenceDerivative.evidence_id == evidence.id)
            .order_by(EvidenceDerivative.created_at)
        )
    )


def reconcile_evidence_storage(db: Session) -> dict[str, int]:
    """Mark incomplete sessions whose quarantine objects no longer exist."""

    storage = get_storage()
    checked = failed = 0
    sessions = db.scalars(
        select(EvidenceUploadSession).where(
            EvidenceUploadSession.status.in_(("created", "uploaded"))
        )
    )
    for session in sessions:
        checked += 1
        if storage.exists(session.quarantine_key):
            continue
        session.status = "failed"
        session.error_message = "Quarantine object is missing"
        session.updated_at = now()
        failed += 1
    if failed:
        db.commit()
    return {"checked": checked, "failed": failed}
