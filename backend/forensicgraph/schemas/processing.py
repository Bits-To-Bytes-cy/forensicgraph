"""Evidence ingestion processing API schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IngestRequest(BaseModel):
    parser_name: str = Field(min_length=1, max_length=120)
    batch_size: int = Field(default=500, ge=1, le=5000)
    reprocess: bool = False


class ProcessingRunResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    evidence_id: str
    case_id: str
    parser_name: str
    parser_version: str
    status: str
    batch_size: int
    attempt: int
    total_records: int
    processed_records: int
    failed_records: int
    next_locator: str | None
    error_summary: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    updated_at: datetime


class ProcessingErrorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    processing_run_id: str
    source_locator: str | None
    error_type: str
    message: str
    details: str
    created_at: datetime
