"""HTTP API for the ForensicGraph investigation workflow."""

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from forensicgraph.evidence import sha256_file
from forensicgraph.attack_graph import analyze_attack_graph
from forensicgraph.timeline import reconstruct_timeline
from forensicgraph.storage import CaseStore

app = FastAPI(
    title="ForensicGraph API",
    version="0.1.0",
    description="Evidence integrity services for authorized digital-forensics investigations.",
)
_dashboard = Path(__file__).parent / "static" / "index.html"
_case_store = CaseStore(os.getenv("FORENSICGRAPH_DB_PATH", "forensicgraph.db"))


class EvidenceManifest(BaseModel):
    """Verifiable metadata for a collected evidence item."""

    model_config = ConfigDict(frozen=True)

    evidence_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    collected_at: datetime


class EvidenceHashRequest(BaseModel):
    path: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    source: str = Field(min_length=1)


class EvidenceVerifyRequest(BaseModel):
    path: str = Field(min_length=1)
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class TimelineEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(min_length=1)
    occurred_at: datetime
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    actor: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class TimelineRequest(BaseModel):
    events: list[TimelineEvent] = Field(min_length=1, max_length=10_000)


class AttackGraphRequest(BaseModel):
    events: list[TimelineEvent] = Field(min_length=1, max_length=10_000)


class IncidentReportRequest(BaseModel):
    case_id: str = Field(min_length=1)
    events: list[TimelineEvent] = Field(min_length=1, max_length=10_000)


class CaseCreateRequest(BaseModel):
    case_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2_000)


class CaseEventRequest(BaseModel):
    events: list[TimelineEvent] = Field(min_length=1, max_length=50_000)


class CustodyEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    sequence: int = Field(ge=1)
    action: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    recorded_at: datetime
    previous_digest: str
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class CustodyRequest(BaseModel):
    action: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(_dashboard)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "forensicgraph"}


@app.post("/v1/cases", status_code=201)
def create_case(request: CaseCreateRequest) -> dict[str, Any]:
    try:
        return _case_store.create_case(
            request.case_id, request.title, request.description
        )
    except sqlite3.IntegrityError as error:
        raise HTTPException(status_code=409, detail="Case already exists") from error


@app.get("/v1/cases")
def list_cases() -> list[dict[str, Any]]:
    return _case_store.list_cases()


@app.get("/v1/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    try:
        return _case_store.get_case(case_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Case was not found") from error


@app.post("/v1/cases/{case_id}/events")
def ingest_case_events(case_id: str, request: CaseEventRequest) -> dict[str, Any]:
    try:
        _case_store.get_case(case_id)
    except KeyError as error:
        raise HTTPException(status_code=404, detail="Case was not found") from error
    return _case_store.upsert_events(
        case_id, [event.model_dump() for event in request.events]
    )


@app.post("/v1/evidence/hash", response_model=EvidenceManifest)
def hash_evidence(request: EvidenceHashRequest) -> EvidenceManifest:
    """Hash a local lab evidence file and return its signed-manifest payload."""
    path = Path(request.path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file was not found")

    return EvidenceManifest(
        evidence_id=request.evidence_id,
        source=request.source,
        sha256=sha256_file(path),
        collected_at=datetime.now(timezone.utc),
    )


@app.post("/v1/evidence/verify")
def verify_evidence(request: EvidenceVerifyRequest) -> dict[str, bool | str]:
    """Re-hash evidence and compare it with a previously recorded digest."""
    path = Path(request.path)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file was not found")
    actual_sha256 = sha256_file(path)
    return {
        "valid": actual_sha256 == request.expected_sha256,
        "expected_sha256": request.expected_sha256,
        "actual_sha256": actual_sha256,
    }


@app.post("/v1/timeline/reconstruct", response_model=list[TimelineEvent])
def timeline(request: TimelineRequest) -> list[TimelineEvent]:
    """Normalize and deterministically order events from multiple evidence sources."""
    return [
        TimelineEvent.model_validate(event)
        for event in reconstruct_timeline(
            [event.model_dump() for event in request.events]
        )
    ]


@app.post("/v1/attack-graph/analyze")
def attack_graph(request: AttackGraphRequest) -> dict[str, Any]:
    """Return explainable attack-path edges and risk findings."""
    events = [event.model_dump() for event in request.events]
    return analyze_attack_graph(events)


@app.post("/v1/cases/report")
def incident_report(request: IncidentReportRequest) -> dict[str, Any]:
    """Create a reproducible investigation summary from normalized events."""
    timeline_events = reconstruct_timeline(
        [event.model_dump() for event in request.events]
    )
    graph = analyze_attack_graph(timeline_events)
    report = {
        "case_id": request.case_id,
        "generated_at": datetime.now(timezone.utc),
        "event_count": len(timeline_events),
        "timeline": timeline_events,
        "attack_graph": graph,
        "custody": {
            **_case_store.verify_custody(),
        },
    }
    try:
        _case_store.save_report(request.case_id, report)
        _case_store.upsert_events(request.case_id, timeline_events)
    except KeyError:
        pass
    return report


@app.post("/v1/custody", response_model=CustodyEntry)
def append_custody_entry(request: CustodyRequest) -> CustodyEntry:
    """Append a hash-chained chain-of-custody entry for an evidence item."""
    return CustodyEntry.model_validate(
        _case_store.append_custody(
            request.action, request.actor, request.evidence_id
        )
    )


@app.get("/v1/custody", response_model=list[CustodyEntry])
def custody_log() -> list[CustodyEntry]:
    return [CustodyEntry.model_validate(entry) for entry in _case_store.list_custody()]


@app.get("/v1/custody/verify")
def verify_custody_log() -> dict[str, bool | int]:
    return _case_store.verify_custody()
