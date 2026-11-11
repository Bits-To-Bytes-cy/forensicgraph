"""Evidence Vault API schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvidenceUploadCreate(BaseModel):
    original_filename: str = Field(min_length=1, max_length=255)
    media_type: str = Field(min_length=1, max_length=160)
    expected_size: int | None = Field(default=None, ge=0)


class EvidenceUploadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    original_filename: str
    media_type: str
    expected_size: int | None
    bytes_received: int
    status: str
    created_at: datetime
    updated_at: datetime


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    organization_id: str
    evidence_number: int
    original_filename: str
    media_type: str
    size_bytes: int
    sha256: str
    sha512: str
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    verified_at: datetime | None


class IntegrityCheckResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: str
    sha256: str
    sha512: str
    size_bytes: int
    storage_readback: bool
    hashes_match: bool
    chain_valid: bool
    details: str
    checked_at: datetime


class CustodyEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: str
    sequence_number: int
    event_type: str
    actor_id: str
    occurred_at: datetime
    payload: str
    previous_hash: str | None
    event_hash: str


class EvidenceDerivativeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: str
    original_filename: str
    media_type: str
    purpose: str
    size_bytes: int
    sha256: str
    sha512: str
    created_by: str
    created_at: datetime
